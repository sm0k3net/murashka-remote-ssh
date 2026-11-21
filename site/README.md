# Project website

The website is static HTML, CSS and JavaScript. The GitHub Pages workflow publishes only this directory and the selected synthetic screenshots.

Repository owners can enable it in **Settings → Pages → Build and deployment → Source → GitHub Actions**. Run **Publish project website** from the Actions tab to deploy. Changes to the site and screenshots on the default branch trigger subsequent deployments.

To preview locally, copy screenshots into the site's asset directory and serve the repository root:

    mkdir -p site/assets
    cp docs/screenshots/*.png site/assets/
    python3 -m http.server 8080 --bind 127.0.0.1

Open http://localhost:8080/site/.
