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
extensions = ["sphinx.ext.autodoc", "sphinx.ext.viewcode", "sphinx.ext.intersphinx"]
source_suffix = [".rst", ".md"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]
pygments_style = "sphinx"
intersphinx_mapping = {
    "https://docs.python.org/3": None,
}

if "readthedocs.org" in os.getcwd().split("/"):
    with open("index.rst", "w") as fh:
        fh.write("Documentation for this project has moved to https://pyauth.github.io/pyotp")
else:
    import guzzle_sphinx_theme

    html_theme_path = guzzle_sphinx_theme.html_theme_path()
    html_theme = "guzzle_sphinx_theme"
    html_theme_options = {
        "project_nav_name": project,
        "projectlink": "https://github.com/pyauth/pyotp",
    }
    html_sidebars = {
        "**": [
            "logo-text.html",
            # "globaltoc.html",
            "localtoc.html",
            "searchbox.html",
        ]
    }
