# Project website

The website is static HTML, CSS and JavaScript. Its source is site/index.html. The root Jekyll entry point uses that same source and rewrites local asset paths to match the repository layout.

The project's GitHub Pages source is **Deploy from a branch → main → / (root)**. GitHub builds on pushes to main. The root configuration excludes the application and release documentation from the website while keeping the synthetic screenshots.

If the repository is configured to use GitHub Actions as its Pages source instead, run **Publish project website** from the Actions tab. That workflow packages the static site and selected screenshots.

To preview locally, copy screenshots into the site's asset directory and serve the repository root:

    mkdir -p site/assets
    cp docs/screenshots/*.png site/assets/
    python3 -m http.server 8080 --bind 127.0.0.1

Open http://localhost:8080/site/.
