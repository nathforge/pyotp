import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

project = "PyOTP"
copyright = "PyOTP contributors"
author = "PyOTP contributors"
version = ""
release = ""
language = "en"
master_doc = "index"
extensions = ["sphinx.ext.autodoc", "sphinx.ext.viewcode", "sphinx.ext.intersphinx", "sphinxext.opengraph"]
source_suffix = [".rst", ".md"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]
pygments_style = "sphinx"
intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
}
templates_path = [""]
ogp_site_url = "https://pyauth.github.io/pyotp/"

if "readthedocs.org" in os.getcwd().split("/"):
    with open("index.rst", "w") as fh:
        fh.write("Documentation for this project has moved to https://pyauth.github.io/pyotp")
else:
    html_theme = "furo"
    html_sidebars = {
        "**": [
            "sidebar/brand.html",
            "sidebar/search.html",
            "sidebar/scroll-start.html",
            "toc.html",
            "sidebar/scroll-end.html",
        ]
    }
