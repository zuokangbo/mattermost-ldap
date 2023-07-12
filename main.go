package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	gcfg "gopkg.in/gcfg.v1"
)

/*
go运行方式：
（1）解释运行
go run main.go
（2）编译运行
--使用默认名
go build main.go
./main
--指定可执行程序名
go build -o test main.go
./test
*/

const (
	LOCAL_PATH_STATIC    = "./static/"
	LOCAL_PATH_TEMPLATES = "./templates/"
	WEB_PATH_STATIC      = "/static/"
	WEB_PATH_LOGIN       = "/oauth/authorize"
	WEB_PATH_TOKEN       = "/oauth/token"
	WEB_PATH_INFO        = "/oauth/userinfo"
)

var LDAP_CONNECT *ldap.Conn
var (
	bindusername = ""
	bindpassword = ""
	base_url_str = "127.0.0.1:8081"
	http_type    = "http"
)

type OpenidConfiguration struct {
	Issuer                                string   `json:"issuer"`
	Authorization_endpoint                string   `json:"authorization_endpoint"`
	Token_endpoint                        string   `json:"token_endpoint"`
	Revocation_endpoint                   string   `json:"revocation_endpoint"`
	Introspection_endpoint                string   `json:"introspection_endpoint"`
	Userinfo_endpoint                     string   `json:"userinfo_endpoint"`
	Jwks_uri                              string   `json:"jwks_uri"`
	Scopes_supported                      []string `json:"scopes_supported"`
	Response_types_supported              []string `json:"response_types_supported"`
	Response_modes_supported              []string `json:"response_modes_supported"`
	Grant_types_supported                 []string `json:"grant_types_supported"`
	Token_endpoint_auth_methods_supported []string `json:"token_endpoint_auth_methods_supported"`
	Subject_types_supported               []string `json:"subject_types_supported"`
	Id_token_signing_alg_values_supported []string `json:"id_token_signing_alg_values_supported"`
	Claim_types_supported                 []string `json:"claim_types_supported"`
	Claims_supported                      []string `json:"claims_supported"`
	Code_challenge_methods_supported      []string `json:"code_challenge_methods_supported"`
}

type TokenData struct {
	Access_token  string `json:"access_token"`
	Token_type    string `json:"token_type"`
	Expires_in    uint   `json:"expires_in"`
	Refresh_token string `json:"refresh_token"`
	Created_at    int64  `json:"created_at"`
}

type UserInfo struct {
	Sub                string   `json:"sub"`
	Auth_time          int64    `json:"auth_time"`
	Name               string   `json:"name"`
	Nickname           string   `json:"nickname"`
	Preferred_username string   `json:"preferred_username"`
	Email              string   `json:"email"`
	Email_verified     bool     `json:"email_verified"`
	Groups             []string `json:"groups"`
}

type LdapConfig struct {
	BindDn       string
	BindPassword string
	BindUrl      string
	QueryDn      string
}

type URLConfig struct {
	Http_type string
	Base_url  string
}

type Config struct {
	Ldap LdapConfig
	RUL  URLConfig
}

func ParseConfig() (cfg Config) {
	err := gcfg.ReadFileInto(&cfg, "config_sample.ini")

	if err != nil {
		log.Fatal(err)
	}

	return
}

func login(w http.ResponseWriter, r *http.Request) {
	redirect_uri := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")

	if redirect_uri == "" {
		page, _ := template.ParseFiles(LOCAL_PATH_TEMPLATES + "error_page.html")
		page.Execute(w, nil)
		return
	}

	if r.Method == "GET" {
		t, _ := template.ParseFiles(LOCAL_PATH_TEMPLATES + "login.html")
		t.Execute(w, nil)
	} else {

		r.ParseForm()
		username := r.Form["username"]
		password := r.Form["password"]
		url_value := []string{""}

		login_status, user_info := check_user(username[0], password[0])
		if login_status {
			all_field := strings.Split(user_info, ",")

			for i := 0; i < len(all_field); i++ {
				if strings.HasPrefix(all_field[i], "CN=") {
					cn_name := strings.Split(all_field[i], "=")[1]
					code_info := base64.StdEncoding.EncodeToString([]byte(cn_name + "_-_" + username[0]))
					url_value[0] = redirect_uri + "?code=" + strings.Replace(code_info, "=", "asdfghjkl00", -1) + "&state=" + state
					break
				}
			}
			http.Redirect(w, r, url_value[0], 301)
			fmt.Println(r.URL.Path, "登录成功")
		} else {
			fmt.Println(r.URL.Path, "登录失败")
			fmt.Fprintf(w, "登录失败")
		}
	}
}

func check_user(username string, password string) (bool, string) {
	if username == "" {
		return false, ""
	}

	if password == "" {
		return false, ""
	}
	return LDAP_auth(username, password)
}

func create_token(w http.ResponseWriter, r *http.Request) {
	//  client_id=&client_secret=&code=1231&grant_type=authorization_code&redirect_uri=https%3A%2F%2Frc-sz-2.hytch.com%2Fsignup%2Fgitlab%2Fcomplete
	println("get token")

	if r.Method != "POST" {
		return
	}

	body, err := ioutil.ReadAll(r.Body)

	if err != nil {
		fmt.Printf("read body err, %v\n", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	content_text := strings.Split(string(body), "&")
	code_string := []string{""}
	for i := 0; i < len(content_text); i++ {
		if strings.HasPrefix(content_text[i], "code=") {
			code_string[0] = strings.Replace(strings.Replace(content_text[i], "code=", "", -1), "=", "asdfghjkl00", -1)
			break
		}
	}

	user_token := TokenData{
		Access_token:  code_string[0],
		Token_type:    "bearer",
		Expires_in:    72000,
		Refresh_token: "a138a15efa4d75562e6f879784685b863c148fd63f4b756c4b4856a52884de0d",
		Created_at:    time.Now().Unix(),
	}
	jsonBytes, err := json.Marshal(user_token)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(jsonBytes)

}

func get_current_info(w http.ResponseWriter, r *http.Request) {
	// Authorization:Bearer c97d1fe52119f38c7f67f0a14db68d60caa35ddc86fd12401718b649dcfa9c68
	user_data := r.Header.Get("Authorization")
	if user_data == "" {
		println("get Authorization error")
		return
	}
	user_code := strings.Split(user_data, " ")[1]
	user_datas, err := base64.StdEncoding.DecodeString(strings.Replace(user_code, "asdfghjkl00", "=", -1))
	if err != nil {
		fmt.Println(err)
	}
	user_list := strings.Split(string(user_datas), "_-_")
	println(user_list[0])

	user_info := UserInfo{
		Sub:                user_list[1],
		Name:               user_list[0],
		Nickname:           user_list[1],
		Preferred_username: user_list[1],
		Email:              user_list[1] + "@hyvision.com",
		Email_verified:     true,
		Groups:             []string{""},
		Auth_time:          time.Now().Unix(),
	}
	jsonBytes, err := json.Marshal(user_info)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(jsonBytes)
}

func openid_config(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		base_url := http_type + "://" + base_url_str

		open_id := OpenidConfiguration{
			Issuer:                                base_url,
			Authorization_endpoint:                base_url + "/oauth/authorize",
			Token_endpoint:                        base_url + "/oauth/token",
			Revocation_endpoint:                   base_url + "/oauth/revoke",
			Introspection_endpoint:                base_url + "/oauth/introspect",
			Userinfo_endpoint:                     base_url + "/oauth/userinfo",
			Jwks_uri:                              base_url + "/oauth/discovery/keys",
			Scopes_supported:                      []string{"api", "read_api", "read_user", "read_repository", "write_repository", "read_observability", "write_observability", "sudo", "admin_mode", "openid", "profile", "email"},
			Response_types_supported:              []string{"code"},
			Response_modes_supported:              []string{"query", "fragment", "form_post"},
			Grant_types_supported:                 []string{"authorization_code", "password", "client_credentials", "refresh_token"},
			Token_endpoint_auth_methods_supported: []string{"client_secret_basic", "client_secret_post"},
			Subject_types_supported:               []string{"public"},
			Id_token_signing_alg_values_supported: []string{"RS256"},
			Claim_types_supported:                 []string{},
			Claims_supported:                      []string{},
			Code_challenge_methods_supported:      []string{"RS256"},
		}
		jsonBytes, err := json.Marshal(open_id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		w.Header().Set("Content-Type", "application/json")

		w.Write(jsonBytes)

	}
}

func gitlabuser(w http.ResponseWriter, r *http.Request) {
	fmt.Println("gitlabuser", r.URL.Query())
	body, err := ioutil.ReadAll(r.Body)
	fmt.Println("gitlabuser json:", string(body))
	if err != nil {
		fmt.Printf("read body err, %v\n", err)
		return
	}

}

func CommonHandle() {
	http.Handle(WEB_PATH_STATIC, http.StripPrefix(WEB_PATH_STATIC, http.FileServer(http.Dir(LOCAL_PATH_STATIC))))
	http.HandleFunc(WEB_PATH_LOGIN, login)
	http.HandleFunc(WEB_PATH_TOKEN, create_token)
	http.HandleFunc(WEB_PATH_INFO, get_current_info)
	http.HandleFunc("/openid-config", openid_config)
	http.HandleFunc("/api/v4/user", gitlabuser)
}

func LDAP_auth(username string, password string) (bool, string) {
	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		"dc=digital,dc=com",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(objectClass=organizationalPerson)(SAMAccountName=%s))", username),
		[]string{"dn"},
		nil,
	)

	sr, err := LDAP_CONNECT.Search(searchRequest)
	if err != nil {
		log.Fatal(err)
		return false, ""
	}

	if len(sr.Entries) != 1 {
		log.Fatal("User does not exist or too many entries returned")
		return false, ""
	}

	userdn := sr.Entries[0].DN
	// CN=左康波,OU=TD部,OU=技术中心,OU=,DC=digital,DC=com
	// Bind as the user to verify their password
	err = LDAP_CONNECT.Bind(userdn, password)
	if err != nil {
		log.Fatal(err)
		return false, ""
	}

	err = LDAP_CONNECT.Bind(bindusername, bindpassword)
	if err != nil {
		log.Fatal(err)
	}
	println("login success", username)
	return true, userdn
}

func main() {
	println("start success")

	ldap_test := ParseConfig()
	l, err := ldap.DialURL("ldap://digital.com:389")
	LDAP_CONNECT = l
	if err != nil {
		log.Fatal(err)
		return
	}
	defer LDAP_CONNECT.Close()

	// First bind with a read only user
	bindusername = ldap_test.Ldap.BindDn
	bindpassword = ldap_test.Ldap.BindPassword
	base_url_str = ldap_test.RUL.Base_url
	http_type = ldap_test.RUL.Http_type

	err = LDAP_CONNECT.Bind(ldap_test.Ldap.BindDn, ldap_test.Ldap.BindPassword)
	if err != nil {
		log.Fatal(err)
		return
	}
	println("load ldap done")

	CommonHandle()
	//监听8181端口
	err = http.ListenAndServe(base_url_str, nil)
	if err != nil {
		log.Fatal("err:", err)
	}

}
