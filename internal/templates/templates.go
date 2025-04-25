package templates

import (
	"embed"
	"html/template"
	"io/fs"

	"github.com/gin-gonic/gin"
)

//go:embed *.html
var TemplateFS embed.FS

// LoadTemplates loads the embedded templates into the Gin engine
func LoadTemplates(router *gin.Engine) error {
	tmpl := template.New("")

	// Read all template files
	files, err := fs.ReadDir(TemplateFS, ".")
	if err != nil {
		return err
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		fileName := file.Name()
		content, err := TemplateFS.ReadFile(fileName)
		if err != nil {
			return err
		}

		_, err = tmpl.New(fileName).Parse(string(content))
		if err != nil {
			return err
		}
	}

	router.SetHTMLTemplate(tmpl)
	return nil
}
