// Command webdemo is a web demo of the data tiering use case, in Japanese,
// for people who are not engineers: a resident sends an inquiry on a city's
// website, gets a receipt, and later checks on an independent site whether
// the inquiry was moved off the outsourced form service and deleted as the
// city promised, including on the day the form service's breach is in the
// news.
//
//	go run ./examples/data-tiering/webdemo
//
// Then open http://localhost:8090/ (the city) and use the demo panel at the
// bottom to let time pass. The checking site runs on http://localhost:8091/.
package main

import (
	"embed"
	"encoding/base64"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/deedlog/deedlog/core"
)

//go:embed assets
var assets embed.FS

var tmpl = template.Must(template.ParseFS(assets, "assets/*.html"))

// demoPanel is the data for the demo panel.
type demoPanel struct {
	City         string
	Date         string
	TransferDown bool
}

var weekdays = []string{"日", "月", "火", "水", "木", "金", "土"}

func jdate(t time.Time) string {
	return fmt.Sprintf("%d年%d月%d日（%s）", t.Year(), t.Month(), t.Day(), weekdays[t.Weekday()])
}

type site struct {
	world     *World
	cityURL   string
	verifyURL string
}

func (s *site) panel() demoPanel {
	st := s.world.State()
	return demoPanel{City: s.cityURL, Date: jdate(st.Now), TransferDown: st.TransferDown}
}

type cityPage struct {
	Title, Page  string
	Breach       bool
	BreachDate   string
	Number, Date string
	ReceiptURL   template.URL
	Demo         demoPanel
}

func (s *site) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, name, data); err != nil {
		log.Print(err)
	}
}

func (s *site) cityPage(title, page string) cityPage {
	st := s.world.State()
	p := cityPage{Title: title, Page: page, Demo: s.panel()}
	if !st.BreachAt.IsZero() {
		p.Breach, p.BreachDate = true, jday(st.BreachAt)
	}
	return p
}

func (s *site) city() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /style.css", serveCSS)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		s.render(w, "city", s.cityPage("ホーム", "home"))
	})
	mux.HandleFunc("GET /contact", func(w http.ResponseWriter, r *http.Request) {
		s.render(w, "city", s.cityPage("お問い合わせ", "contact"))
	})
	mux.HandleFunc("POST /contact", func(w http.ResponseWriter, r *http.Request) {
		index, receipt, err := s.world.Submit(r.FormValue("name"), r.FormValue("email"), r.FormValue("message"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		q := url.Values{"n": {strconv.FormatUint(index, 10)}, "r": {base64.RawURLEncoding.EncodeToString(receipt)}}
		http.Redirect(w, r, "/contact/done?"+q.Encode(), http.StatusSeeOther)
	})
	mux.HandleFunc("GET /contact/done", func(w http.ResponseWriter, r *http.Request) {
		note, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("r"))
		if err != nil {
			http.Error(w, "bad receipt", http.StatusBadRequest)
			return
		}
		p := s.cityPage("送信完了", "done")
		n, _ := strconv.ParseUint(r.URL.Query().Get("n"), 10, 64)
		p.Number, p.Date = fmt.Sprintf("R-%06d", n), jdate(s.world.State().Now)
		p.ReceiptURL = template.URL(core.ReceiptURL(s.verifyURL+"/status", note))
		s.render(w, "city", p)
	})
	mux.HandleFunc("GET /news/breach", func(w http.ResponseWriter, r *http.Request) {
		s.render(w, "city", s.cityPage("お知らせ", "breach"))
	})

	// The publication API: what anyone may fetch to check the city.
	publish := func(pick func(cp, chain, policy []byte) []byte) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Write(pick(s.world.Published()))
		}
	}
	mux.HandleFunc("GET /deedlog/checkpoint", publish(func(cp, _, _ []byte) []byte { return cp }))
	mux.HandleFunc("GET /deedlog/chain", publish(func(_, chain, _ []byte) []byte { return chain }))
	mux.HandleFunc("GET /deedlog/policy", publish(func(_, _, p []byte) []byte { return p }))

	// The demo panel's controls.
	mux.HandleFunc("POST /demo/{action}", func(w http.ResponseWriter, r *http.Request) {
		var err error
		switch r.PathValue("action") {
		case "advance":
			days, _ := strconv.Atoi(r.URL.Query().Get("days"))
			err = s.world.Advance(min(max(days, 1), 60))
		case "transfer":
			s.world.SetTransferDown(r.URL.Query().Get("down") == "1")
		case "breach":
			s.world.Breach()
		case "tamper":
			err = s.world.Tamper()
		case "reset":
			err = s.world.Reset()
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		back := r.FormValue("back")
		if !strings.HasPrefix(back, s.cityURL) && !strings.HasPrefix(back, s.verifyURL) {
			back = s.cityURL + "/"
		}
		http.Redirect(w, r, back, http.StatusSeeOther)
	})
	return mux
}

func (s *site) verifier(v *Verifier) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /style.css", serveCSS)
	page := func(w http.ResponseWriter, r *http.Request) {
		s.render(w, "verify", struct{ Demo demoPanel }{s.panel()})
	}
	mux.HandleFunc("GET /{$}", page)
	mux.HandleFunc("GET /status", page)
	mux.HandleFunc("GET /about", func(w http.ResponseWriter, r *http.Request) {
		s.render(w, "about", struct{ Demo demoPanel }{s.panel()})
	})
	mux.Handle("GET /api/status", v)
	return mux
}

func serveCSS(w http.ResponseWriter, r *http.Request) {
	b, _ := assets.ReadFile("assets/style.css")
	w.Header().Set("Content-Type", "text/css")
	w.Write(b)
}

func main() {
	cityAddr := flag.String("city", "localhost:8090", "address of the city's website")
	verifyAddr := flag.String("verify", "localhost:8091", "address of the checking site")
	flag.Parse()

	world, err := NewWorld()
	if err != nil {
		log.Fatal(err)
	}
	defer world.Close()
	s := &site{world: world, cityURL: "http://" + *cityAddr, verifyURL: "http://" + *verifyAddr}
	v := &Verifier{CityURL: s.cityURL, Keys: world.Keys, News: func() time.Time { return world.State().BreachAt }}

	go func() { log.Fatal(http.ListenAndServe(*verifyAddr, s.verifier(v))) }()
	fmt.Printf("あおば台市（デモ）:   %s/\n記録確認ネット:     %s/\n", s.cityURL, s.verifyURL)
	log.Fatal(http.ListenAndServe(*cityAddr, s.city()))
}
