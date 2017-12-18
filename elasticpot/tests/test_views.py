import json
import unittest

from bottle import response
from elasticpot import views


class TestViews(unittest.TestCase):

    def test_404(self):
        error404 = json.loads(views.error404(None))
        assert error404["status"] == 404
        assert response.content_type == "application/json"

    def test_index(self):
        index = json.loads(views.index())
        assert index["name"] == "Flake"
        assert response.content_type == "application/json"

    def test_favicon(self):
        favicon = views.favicon()
        assert favicon == ""

    def test_getindices(self):
        indices = views.getindeces()
        assert "yellow" in indices

    def test_handleSearchExploitGet(self):
        assert views.handleSearchExploitGet() == ""

    def test_handleSearchExploit(self):
        assert views.handleSearchExploit() == ""

    def test_pluginhead(self):
        pluginhead = views.pluginhead()
        assert "elasticsearch-head" in pluginhead
        assert response.content_type == "text/html"
