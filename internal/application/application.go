package application

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"path/filepath"

	"strings"
	"time"

	"github.com/alextonkonogov/atonko-authorization/internal/repository"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/julienschmidt/httprouter"
)

type app struct {
	ctx   context.Context
	repo  *repository.Repository
	cache map[string]repository.User
}

func (a app) Routes(r *httprouter.Router) {
	r.GET("/", a.authorized(a.MainPage))
	r.GET("/login", func(rw http.ResponseWriter, r *http.Request, p httprouter.Params) {
		a.LoginPage(rw, "")
	})
	r.POST("/login", a.Login)
	r.GET("/logout", a.Logout)
	r.GET("/signup", func(rw http.ResponseWriter, r *http.Request, p httprouter.Params) {
		a.SignupPage(rw, "")
	})
	r.POST("/signup", a.Signup)

	r.GET("/profil", a.authorized(a.Profil))
	r.GET("/purchase", a.authorized(a.Purchase))

	r.POST("/saveAbout", a.Profil)

}

func (a app) authorized(next httprouter.Handle) httprouter.Handle {
	return func(rw http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		token, err := readCookie("token", r)

		if err != nil {
			http.Redirect(rw, r, "/login", http.StatusSeeOther)
			return
		}

		if _, ok := a.cache[token]; !ok {
			http.Redirect(rw, r, "/login", http.StatusSeeOther)
			return
		}

		next(rw, r, ps)
	}
}

func (a *app) getCurrentUserID(r *http.Request) int {
	token, err := readCookie("token", r)
	if err != nil {
		return 0
	}

	user, ok := a.cache[token]
	if !ok {
		return 0
	}

	return user.ID
}

func (a app) LoginPage(rw http.ResponseWriter, message string) {
	lp := filepath.Join("public", "html", "login.html")

	tmpl, err := template.ParseFiles(lp)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	type answer struct {
		Message string
	}
	data := answer{message}

	err = tmpl.ExecuteTemplate(rw, "login", data)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
}

func (a app) Login(rw http.ResponseWriter, r *http.Request, p httprouter.Params) {
	email := r.FormValue("email")
	password := r.FormValue("password")

	if email == "" || password == "" {
		a.LoginPage(rw, "Необходимо указать почту и пароль!")
		return
	}

	hash := md5.Sum([]byte(password))
	hashedPass := hex.EncodeToString(hash[:])

	user, err := a.repo.Login(a.ctx, email, hashedPass)
	if err != nil {
		a.LoginPage(rw, "Вы ввели неверную почту или пароль!")
		return
	}

	time64 := time.Now().Unix()
	timeInt := string(rune(time64))
	token := email + password + timeInt

	hashToken := md5.Sum([]byte(token))
	hashedToken := hex.EncodeToString(hashToken[:])

	a.cache[hashedToken] = user

	livingTime := 60 * time.Minute
	expiration := time.Now().Add(livingTime)
	cookie := http.Cookie{Name: "token", Value: url.QueryEscape(hashedToken), Expires: expiration}
	http.SetCookie(rw, &cookie)
	http.Redirect(rw, r, "/", http.StatusSeeOther)
}

func (a app) Logout(rw http.ResponseWriter, r *http.Request, p httprouter.Params) {
	for _, v := range r.Cookies() {
		c := http.Cookie{
			Name:   v.Name,
			MaxAge: -1}
		http.SetCookie(rw, &c)
	}
	http.Redirect(rw, r, "/login", http.StatusSeeOther)
}

func (a app) SignupPage(rw http.ResponseWriter, message string) {
	sp := filepath.Join("public", "html", "signup.html")

	tmpl, err := template.ParseFiles(sp)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	type answer struct {
		Message string
	}
	data := answer{message}

	err = tmpl.ExecuteTemplate(rw, "signup", data)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
}

func (a app) Signup(rw http.ResponseWriter, r *http.Request, p httprouter.Params) {
	name := strings.TrimSpace(r.FormValue("name"))
	email := strings.TrimSpace(r.FormValue("email"))
	password := strings.TrimSpace(r.FormValue("password"))

	if name == "" || email == "" || password == "" {
		a.SignupPage(rw, "Все поля должны быть заполнены!")
		return
	}

	hash := md5.Sum([]byte(password))
	hashedPass := hex.EncodeToString(hash[:])

	err := a.repo.AddNewUser(a.ctx, name, email, hashedPass)
	if err != nil {
		a.SignupPage(rw, fmt.Sprintf("Ошибка создания пользователя: %v", err))
		return
	}

	a.LoginPage(rw, fmt.Sprintf("%s, вы успешно зарегистрированы! Теперь вам доступен вход через страницу авторизации", name))
}

func (a app) Profil(rw http.ResponseWriter, r *http.Request, p httprouter.Params) {
	userID := a.getCurrentUserID(r)
	if userID == 0 {
		http.Redirect(rw, r, "/login", http.StatusSeeOther)
		return
	}

	// Получение данных о пользователе из таблицы users
	user, err := a.repo.GetUserByID(a.ctx, userID)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	// Получение данных о пользователе из таблицы user_info
	userAbout, err := a.repo.GetAboutByID(a.ctx, userID)
	if err != nil {
		if strings.Contains(err.Error(), "no rows in result set") {
			// Если записи о пользователе в таблице user_info не существует, создаем пустую запись
			err = a.repo.UpdateAbout(a.ctx, userID, "")
			if err != nil {
				http.Error(rw, err.Error(), http.StatusInternalServerError)
				return
			}
			userAbout = "" // Присваиваем пустую строку, чтобы избежать ошибки отображения
		} else {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Составление данных для передачи в шаблон
	type ProfileData struct {
		Name  string
		Email string
		About string
	}

	data := ProfileData{
		Name:  user.Name,
		Email: user.Email,
		About: userAbout,
	}

	// Обработка POST-запроса для сохранения информации о пользователе
	if r.Method == http.MethodPost {
		// Получение нового значения поля "О себе" из тела запроса
		type AboutRequest struct {
			About string `json:"about"`
		}

		var aboutReq AboutRequest
		if err := json.NewDecoder(r.Body).Decode(&aboutReq); err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}

		// Сохранение нового значения поля "О себе" в базе данных в таблице user_info
		err := a.repo.UpdateAbout(a.ctx, userID, aboutReq.About)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		// Обновление данных о пользователе для отображения
		data.About = aboutReq.About
	}

	// Парсинг шаблона и передача данных в него
	lp := filepath.Join("public", "html", "profil.html")
	tmpl, err := template.ParseFiles(lp)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	err = tmpl.ExecuteTemplate(rw, "profil", data)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
}

func (a app) MainPage(rw http.ResponseWriter, r *http.Request, p httprouter.Params) {
	lp := filepath.Join("public", "html", "mainpage.html")
	tmpl, err := template.ParseFiles(lp)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	// ... (можешь подготовить какие-то данные для передачи в шаблон)

	err = tmpl.ExecuteTemplate(rw, "mainpage", nil) // Передача данных в шаблон
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
}

func (a app) Purchase(rw http.ResponseWriter, r *http.Request, p httprouter.Params) {
	lp := filepath.Join("public", "html", "purchase.html")
	tmpl, err := template.ParseFiles(lp)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	// ... (можешь подготовить какие-то данные для передачи в шаблон)

	err = tmpl.ExecuteTemplate(rw, "purchase", nil)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
}

func readCookie(name string, r *http.Request) (value string, err error) {
	if name == "" {
		return value, errors.New("you are trying to read empty cookie")
	}
	cookie, err := r.Cookie(name)
	if err != nil {
		return value, err
	}
	str := cookie.Value
	value, _ = url.QueryUnescape(str)
	return value, err
}

func NewApp(ctx context.Context, dbpool *pgxpool.Pool) *app {
	return &app{ctx, repository.NewRepository(dbpool), make(map[string]repository.User)}
}
