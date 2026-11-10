// Command webdemo is a web demo of the official videos use case, in
// Japanese, for people who are not engineers: a fan watches a video on a
// fan club site and, on an independent checking site, sees how it was made:
// from footage registered at the shoot, edited by a rendering engine under
// the published recipe. Videos with scenes the footage does not contain,
// or edited outside the engine, show up there.
//
//	go run ./examples/official-videos/webdemo
//
// Then open http://localhost:8090/ (the fan club) and use the demo panel
// at the bottom. The checking site runs on http://localhost:8091/.
package main

import (
	"embed"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/eucassoc/deedlog/core"
)

//go:embed assets
var assets embed.FS

var tmpl = template.Must(template.ParseFS(assets, "assets/*.html"))

// demoPanel is the data for the demo panel.
type demoPanel struct {
	Club string
	Date string
}

var weekdays = []string{"日", "月", "火", "水", "木", "金", "土"}

func jdate(t time.Time) string {
	return fmt.Sprintf("%d年%d月%d日（%s）", t.Year(), t.Month(), t.Day(), weekdays[t.Weekday()])
}

type site struct {
	world     *World
	clubURL   string
	verifyURL string
}

func (s *site) panel() demoPanel {
	return demoPanel{Club: s.clubURL, Date: jdate(s.world.Now())}
}

type videoCard struct {
	Video
	DateText   string
	ReceiptURL template.URL
}

type clubPage struct {
	Title, Page string
	Videos      []videoCard
	Video       *videoCard
	Allowed     []string
	Recipe      string
	Demo        demoPanel
}

func (s *site) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, name, data); err != nil {
		log.Print(err)
	}
}

func (s *site) clubPage(title, page string) clubPage {
	p := clubPage{Title: title, Page: page, Demo: s.panel(), Recipe: recipe.Name}
	for _, v := range s.world.Videos() {
		p.Videos = append(p.Videos, videoCard{Video: v, DateText: jdate(v.Date),
			ReceiptURL: template.URL(core.ReceiptURL(s.verifyURL+"/status", v.Receipt))})
	}
	for _, k := range recipe.Allowed {
		p.Allowed = append(p.Allowed, opName(k))
	}
	return p
}

func (s *site) club() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /style.css", serveCSS)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		s.render(w, "club", s.clubPage("ホーム", "home"))
	})
	mux.HandleFunc("GET /videos/{n}", func(w http.ResponseWriter, r *http.Request) {
		p := s.clubPage("公式動画", "video")
		n, _ := strconv.Atoi(r.PathValue("n"))
		for i := range p.Videos {
			if p.Videos[i].N == n {
				p.Video, p.Title = &p.Videos[i], p.Videos[i].Title
			}
		}
		if p.Video == nil {
			http.NotFound(w, r)
			return
		}
		s.render(w, "club", p)
	})
	mux.HandleFunc("GET /recipe", func(w http.ResponseWriter, r *http.Request) {
		s.render(w, "club", s.clubPage("公式動画の編集レシピ", "recipe"))
	})

	// The publication API: what anyone may fetch to check the fan club.
	text := func(w http.ResponseWriter, b []byte) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(b)
	}
	mux.HandleFunc("GET /deedlog/checkpoint", func(w http.ResponseWriter, r *http.Request) {
		cp, _ := s.world.Published()
		text(w, cp)
	})
	mux.HandleFunc("GET /deedlog/chain", func(w http.ResponseWriter, r *http.Request) {
		_, chain := s.world.Published()
		text(w, chain)
	})
	mux.HandleFunc("GET /deedlog/evidence/{digest}", func(w http.ResponseWriter, r *http.Request) {
		b, ok := s.world.Evidence(r.PathValue("digest"))
		if !ok {
			http.NotFound(w, r)
			return
		}
		text(w, b)
	})

	// The demo panel's controls.
	mux.HandleFunc("POST /demo/{action}", func(w http.ResponseWriter, r *http.Request) {
		var err error
		switch r.PathValue("action") {
		case "publish":
			err = s.world.PublishAsDeclared()
		case "generate":
			err = s.world.PublishGenerated()
		case "other-app":
			err = s.world.PublishOtherApp()
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
		if !strings.HasPrefix(back, s.clubURL) && !strings.HasPrefix(back, s.verifyURL) {
			back = s.clubURL + "/"
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
	mux.Handle("GET /api/status", v)
	return mux
}

func serveCSS(w http.ResponseWriter, r *http.Request) {
	b, _ := assets.ReadFile("assets/style.css")
	w.Header().Set("Content-Type", "text/css")
	w.Write(b)
}

func main() {
	clubAddr := flag.String("club", "localhost:8090", "address of the fan club's website")
	verifyAddr := flag.String("verify", "localhost:8091", "address of the checking site")
	flag.Parse()

	world, err := NewWorld()
	if err != nil {
		log.Fatal(err)
	}
	defer world.Close()
	s := &site{world: world, clubURL: "http://" + *clubAddr, verifyURL: "http://" + *verifyAddr}
	v := &Verifier{ClubURL: s.clubURL, Keys: world.Keys}

	go func() { log.Fatal(http.ListenAndServe(*verifyAddr, s.verifier(v))) }()
	fmt.Printf("ファンクラブ（デモ）: %s/\n来歴チェック:         %s/\n", s.clubURL, s.verifyURL)
	log.Fatal(http.ListenAndServe(*clubAddr, s.club()))
}
