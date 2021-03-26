package templates

import (
	"html/template"
	"net/http"

	"k8s.io/klog"
)

var loginSuccess = template.Must(template.New("login-success.html").Parse(`<html>
  <head>
	<style>
	  pre {
		white-space: pre-wrap;       /* css-3 */
		white-space: -moz-pre-wrap;  /* Mozilla, since 1999 */
		white-space: -pre-wrap;      /* Opera 4-6 */
		white-space: -o-pre-wrap;    /* Opera 7 */
		word-wrap: break-word;       /* Internet Explorer 5.5+ */
	  }

	  header{
		display: flex;
		flex-direction: column;
		align-items: center;
	  }

	  div{
		height: 100%;
		background-position: center;
		background-repeat: no-repeat;
		background-size: cover;
	  }

	  .token{
        width: 600px;
        height: 200px;
        
        position:absolute;
        left:0;
        top: 0;
        bottom: 0;
        right: 0;
        margin: auto;
	  }

	  img{
		width: 6rem;
		height: 6rem;
	  }
    </style>
  </head>
  <body>
	<div>
	<header>
	  <img src="https://i.ibb.co/DMsjhRx/mark-success.jpg" alt="mark-success" >
	  <p>{{ .Email }}</p>
	  <p>login successfully, please copy the RawIDToken and close the page</p>
	</header>
	</div>

	<div class="token">
	<p>RawIDToken: <pre><code>{{ .RawIDToken }}</code></pre></p>
	</div>

  </body>
</html>
`))

type loginSuccessData struct {
	Email      string
	RawIDToken string
}

// RenderLoginSuccess ...
func RenderLoginSuccess(w http.ResponseWriter, email, rawIDToken string) {
	renderTemplate(w, loginSuccess, loginSuccessData{Email: email, RawIDToken: rawIDToken})
}

func renderTemplate(w http.ResponseWriter, tmpl *template.Template, data interface{}) {
	err := tmpl.Execute(w, data)
	if err == nil {
		return
	}

	switch err := err.(type) {
	case *template.Error:
		// An ExecError guarantees that Execute has not written to the underlying reader.
		klog.Errorf("Error rendering template %s: %s", tmpl.Name(), err)

		// TODO(ericchiang): replace with better internal server error.
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	default:
		// An error with the underlying write, such as the connection being
		// dropped. Ignore for now.
	}
}
