package templates

import (
	"html/template"
	"net/http"
)

var indexTmpl = template.Must(template.New("index.html").Parse(`<html>
<head>
  <style>
  header{
	display: flex;
	flex-direction: column;
	align-items: center;
  }

  div{
	width: 200px;
	height: 200px;
	
	position:absolute;
	left:0;
	top: 0;
	bottom: 0;
	right: 0;
	margin: auto;
  }
  </style>
</head>
<body>
  <div>
  <header>
    <form action="/login" method="post">
    <p>
      login with the dex account
    </p>
    <p>
      <input type="submit" value="Login">
    </p>
    </form>
  </header>
  </div>
</body>
</html>`))

// RenderIndex ...
func RenderIndex(w http.ResponseWriter) {
	renderTemplate(w, indexTmpl, nil)
}
