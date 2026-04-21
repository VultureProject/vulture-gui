#!/home/vlt-os/env/bin/python
"""This file is part of Vulture OS.

Vulture OS is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

__author__ = "VultureProject contributors"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = "Tests for HAProxy frontend configuration generation (services/frontend/models.py)"


from django.test import TestCase
from unittest.mock import patch, MagicMock

from system.cluster.models import Node, NetworkAddress, NetworkInterfaceCard, NetworkAddressNIC
from system.tenants.models import Tenants
from services.frontend.models import Frontend, Listener


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _make_config_mock():
    """Return a minimal Config-like mock usable as Cluster.get_global_config()"""
    cfg = MagicMock()
    cfg.to_dict.return_value = {
        "cluster_api_key": "test-key",
        "oauth2_header_name": "X-Vlt-Token",
        "portal_cookie_name": "vlt",
        "public_token": "",
        "redis_password": "",
    }
    return cfg



class FrontendConfTestBase(TestCase):
    """
    Base class: creates the minimum DB objects required by generate_conf()
    and patches every external dependency that would require a full
    FreeBSD/MongoDB cluster.
    """

    TEST_CASE_NAME = f"{__name__}"

    # Patches actifs pour la suite
    PATCHES = [
        # Cluster.get_global_config() -> ne pas toucher la DB Config
        "services.frontend.models.Cluster.get_global_config",
        # FilterPolicy.objects.filter() -> darwin, non teste ici
        "services.frontend.models.FilterPolicy.objects.filter",
        # Supprime le bruit de logs pendant les tests
        "services.frontend.models.logger",
    ]

    def setUp(self):
        # Patches
        self.mock_get_global_config = patch(
            "services.frontend.models.Cluster.get_global_config",
            return_value=_make_config_mock()
        ).start()
        self.mock_filter_policy = patch(
            "services.frontend.models.FilterPolicy.objects.filter",
            return_value=[]
        ).start()
        patch("services.frontend.models.logger").start()
        self.addCleanup(patch.stopall)

        # Objets DB
        self.tenants = Tenants.objects.create(name=f"test_tenants_{self.TEST_CASE_NAME}")

    def _make_frontend(self, **kwargs) -> Frontend:
        """
        Construit et sauvegarde un Frontend avec des valeurs sures par defaut.
        Toutes les relations M2M sont vides (listener_list=[], header_list=[]).
        """
        defaults = dict(
            name=f"fe_{id(kwargs)}",
            mode="http",
            enabled=True,
            tenants_config=self.tenants,
            enable_logging=False,
            https_redirect=False,
            custom_haproxy_conf="",
            enable_cache=False,
            enable_compression=False,
            healthcheck_service=False,
            timeout_client=60,
            timeout_keep_alive=500,
            log_level="warning",
            log_condition="",
        )
        defaults.update(kwargs)
        fe = Frontend.objects.create(**defaults)
        return fe

    def _generate(self, frontend: Frontend, listener_list=None, header_list=None) -> str:
        """
        Appelle generate_conf() en injectant des listes vides pour eviter les
        requetes DB sur les relations non testees
        """
        return frontend.generate_conf(
            listener_list=listener_list if listener_list is not None else [],
            header_list=header_list if header_list is not None else [],
        )



class TestHasHaproxyConf(FrontendConfTestBase):
    """
    has_haproxy_conf controle si generate_conf() produit du contenu ou "".
    C'est la premiere couche de defense contre les mauvaises generations.
    """

    def test_mode_http_has_haproxy_conf(self):
        fe = self._make_frontend(mode="http")
        self.assertTrue(fe.has_haproxy_conf)

    def test_mode_tcp_has_haproxy_conf(self):
        fe = self._make_frontend(mode="tcp")
        self.assertTrue(fe.has_haproxy_conf)

    def test_mode_log_tcp_has_haproxy_conf(self):
        fe = self._make_frontend(mode="log", listening_mode="tcp")
        self.assertTrue(fe.has_haproxy_conf)

    def test_mode_log_tcp_udp_has_haproxy_conf(self):
        fe = self._make_frontend(mode="log", listening_mode="tcp,udp")
        self.assertTrue(fe.has_haproxy_conf)

    def test_mode_log_relp_has_haproxy_conf(self):
        fe = self._make_frontend(mode="log", listening_mode="relp")
        self.assertTrue(fe.has_haproxy_conf)

    def test_mode_log_file_no_haproxy_conf(self):
        """Un listener FILE rsyslog-only : pas de conf HAProxy"""
        fe = self._make_frontend(mode="log", listening_mode="file")
        self.assertFalse(fe.has_haproxy_conf)

    def test_mode_log_udp_no_haproxy_conf(self):
        """UDP est gere par rsyslog directement"""
        fe = self._make_frontend(mode="log", listening_mode="udp")
        self.assertFalse(fe.has_haproxy_conf)

    def test_mode_log_redis_no_haproxy_conf(self):
        fe = self._make_frontend(mode="log", listening_mode="redis")
        self.assertFalse(fe.has_haproxy_conf)

    def test_mode_log_kafka_no_haproxy_conf(self):
        fe = self._make_frontend(mode="log", listening_mode="kafka")
        self.assertFalse(fe.has_haproxy_conf)

    def test_mode_log_api_no_haproxy_conf(self):
        fe = self._make_frontend(mode="log", listening_mode="api")
        self.assertFalse(fe.has_haproxy_conf)

    def test_mode_log_file_generates_empty_string(self):
        """generate_conf() doit retourner "" si has_haproxy_conf est False"""
        fe = self._make_frontend(mode="log", listening_mode="file")
        self.assertEqual(self._generate(fe), "")

    def test_mode_filebeat_with_ip_placeholder_has_haproxy_conf(self):
        fe = self._make_frontend(mode="filebeat", filebeat_config="host: %ip%:514")
        self.assertTrue(fe.has_haproxy_conf)

    def test_mode_filebeat_without_ip_placeholder_no_haproxy_conf(self):
        fe = self._make_frontend(mode="filebeat", filebeat_config="host: 127.0.0.1:514")
        self.assertFalse(fe.has_haproxy_conf)



class TestFrontendConfStructure(FrontendConfTestBase):
    """Verifie la structure de base du bloc genere"""

    def test_http_mode_uses_frontend_keyword(self):
        fe = self._make_frontend(mode="http", name="test-http-fe")
        conf = self._generate(fe)
        self.assertIn("frontend test-http-fe", conf)
        self.assertNotIn("listen test-http-fe", conf)

    def test_tcp_mode_uses_frontend_keyword(self):
        fe = self._make_frontend(mode="tcp", name="test-tcp-fe")
        conf = self._generate(fe)
        self.assertIn("frontend test-tcp-fe", conf)

    def test_log_mode_tcp_uses_listen_keyword(self):
        """En mode log+tcp, HAProxy utilise un bloc 'listen' (pas 'frontend')"""
        fe = self._make_frontend(mode="log", listening_mode="tcp", name="test-log-fe")
        conf = self._generate(fe)
        self.assertIn("listen test-log-fe", conf)
        self.assertNotIn("frontend test-log-fe", conf)

    def test_enabled_frontend_has_enabled_directive(self):
        fe = self._make_frontend(mode="http", enabled=True)
        conf = self._generate(fe)
        self.assertIn("enabled", conf)
        self.assertNotIn("disabled", conf)

    def test_disabled_frontend_has_disabled_directive(self):
        fe = self._make_frontend(mode="http", enabled=False)
        conf = self._generate(fe)
        self.assertIn("disabled", conf)

    def test_http_mode_directive_in_conf(self):
        fe = self._make_frontend(mode="http")
        conf = self._generate(fe)
        self.assertIn("mode http", conf)

    def test_tcp_mode_directive_in_conf(self):
        fe = self._make_frontend(mode="tcp")
        conf = self._generate(fe)
        self.assertIn("mode tcp", conf)

    def test_log_mode_tcp_uses_mode_tcp_in_conf(self):
        fe = self._make_frontend(mode="log", listening_mode="tcp")
        conf = self._generate(fe)
        self.assertIn("mode tcp", conf)



class TestFrontendTimeouts(FrontendConfTestBase):
    """
    Timeouts
    """
    def test_timeout_client_appears_in_conf(self):
        fe = self._make_frontend(mode="http", timeout_client=90)
        conf = self._generate(fe)
        self.assertIn("timeout client 90s", conf)

    def test_timeout_keep_alive_appears_in_http_conf(self):
        fe = self._make_frontend(mode="http", timeout_keep_alive=1000)
        conf = self._generate(fe)
        self.assertIn("timeout http-keep-alive 1000", conf)

    def test_timeout_keep_alive_absent_in_tcp_conf(self):
        """Le timeout http-keep-alive n'a pas de sens en mode TCP"""
        fe = self._make_frontend(mode="tcp", timeout_keep_alive=1000)
        conf = self._generate(fe)
        self.assertNotIn("timeout http-keep-alive", conf)

    def test_timeout_server_60s_present_in_log_mode(self):
        """En mode log, HAProxy doit avoir un timeout server fixe"""
        fe = self._make_frontend(mode="log", listening_mode="tcp")
        conf = self._generate(fe)
        self.assertIn("timeout server 60s", conf)



class TestFrontendHttpsRedirect(FrontendConfTestBase):
    """
    Bug historique : https_redirect n'etait rendu que dans le bloc {% if conf.workflows %}.
    """

    def test_https_redirect_true_adds_redirect_scheme(self):
        fe = self._make_frontend(mode="http", https_redirect=True)
        conf = self._generate(fe)
        self.assertIn("redirect scheme https code 301", conf)
        self.assertIn("!{ ssl_fc }", conf)

    def test_https_redirect_false_no_redirect(self):
        fe = self._make_frontend(mode="http", https_redirect=False)
        conf = self._generate(fe)
        self.assertNotIn("redirect scheme https", conf)

    def test_https_redirect_irrelevant_in_tcp_mode(self):
        """Le template ne genere pas de redirect en mode TCP"""
        fe = self._make_frontend(mode="tcp", https_redirect=True)
        conf = self._generate(fe)
        self.assertNotIn("redirect scheme https", conf)



class TestCustomHaproxyConf(FrontendConfTestBase):
    """
    custom_haproxy_conf doit etre injecte verbatim.
    Cas exotique : injection vide ne doit pas laisser d'artefact.
    """

    def test_custom_directives_injected_verbatim(self):
        custom = "option http-server-close\nretries 3"
        fe = self._make_frontend(mode="http", custom_haproxy_conf=custom)
        conf = self._generate(fe)
        self.assertIn("option http-server-close", conf)
        self.assertIn("retries 3", conf)

    def test_single_custom_directive(self):
        fe = self._make_frontend(mode="http", custom_haproxy_conf="option forwardfor")
        conf = self._generate(fe)
        self.assertIn("option forwardfor", conf)

    def test_empty_custom_conf_no_artifact(self):
        """Pas de bloc vide parasite quand custom_haproxy_conf est ''"""
        fe = self._make_frontend(mode="http", custom_haproxy_conf="")
        conf = self._generate(fe)
        # Pas trois newlines consecutifs (signe d'un bloc conditionnel mal rendu)
        self.assertNotIn("\n\n\n", conf)

    def test_custom_conf_with_special_chars(self):
        """Les caracteres speciaux ne doivent pas casser le rendu Jinja"""
        custom = 'http-request set-header X-Real-IP "%[src]"'
        fe = self._make_frontend(mode="http", custom_haproxy_conf=custom)
        conf = self._generate(fe)
        self.assertIn("X-Real-IP", conf)

    def test_custom_conf_multiline_preserved(self):
        custom = "option1\noption2\noption3"
        fe = self._make_frontend(mode="http", custom_haproxy_conf=custom)
        conf = self._generate(fe)
        self.assertIn("option1", conf)
        self.assertIn("option2", conf)
        self.assertIn("option3", conf)



class TestFrontendLogging(FrontendConfTestBase):
    """
    Logging
    """
    def test_http_logging_enabled_adds_option_httplog(self):
        fe = self._make_frontend(mode="http", enable_logging=True, log_level="info")
        conf = self._generate(fe)
        self.assertIn("option httplog", conf)

    def test_tcp_logging_enabled_adds_option_tcplog(self):
        fe = self._make_frontend(mode="tcp", enable_logging=True)
        conf = self._generate(fe)
        self.assertIn("option tcplog", conf)

    def test_logging_disabled_adds_no_log(self):
        fe = self._make_frontend(mode="http", enable_logging=False)
        conf = self._generate(fe)
        self.assertIn("no log", conf)
        self.assertNotIn("option httplog", conf)

    def test_http_logging_includes_unix_socket_path(self):
        """Le socket Unix de communication HAProxy -> rsyslog doit apparaitre"""
        fe = self._make_frontend(mode="http", enable_logging=True)
        conf = self._generate(fe)
        expected_socket = fe.get_unix_socket()
        self.assertIn(expected_socket, conf)

    def test_http_logging_includes_log_level(self):
        fe = self._make_frontend(mode="http", enable_logging=True, log_level="debug")
        conf = self._generate(fe)
        self.assertIn("debug", conf)

    def test_http_logging_captures_user_agent(self):
        """En mode HTTP avec logging, HAProxy doit capturer l'User-Agent"""
        fe = self._make_frontend(mode="http", enable_logging=True)
        conf = self._generate(fe)
        self.assertIn("capture request header User-Agent", conf)

    def test_http_logging_log_format_is_json(self):
        """Le log-format doit etre du JSON (pour etre consomme par rsyslog)"""
        fe = self._make_frontend(mode="http", enable_logging=True)
        conf = self._generate(fe)
        self.assertIn('log-format "{ ', conf)

    def test_http_log_format_has_http_specific_fields(self):
        """En HTTP, des champs specifiques HTTP doivent etre dans le log-format"""
        fe = self._make_frontend(mode="http", enable_logging=True)
        conf = self._generate(fe)
        self.assertIn("http_method", conf)
        self.assertIn("http_path", conf)

    def test_tcp_log_format_no_http_specific_fields(self):
        """En TCP, les champs HTTP ne doivent PAS apparaitre dans le log-format"""
        fe = self._make_frontend(mode="tcp", enable_logging=True)
        conf = self._generate(fe)
        self.assertNotIn("http_method", conf)



class TestFrontendCache(FrontendConfTestBase):
    """
    Cache HTTP
    """

    def test_cache_enabled_creates_cache_section(self):
        fe = self._make_frontend(
            mode="http",
            enable_cache=True,
            cache_total_max_size=16,
            cache_max_age=120,
        )
        conf = self._generate(fe)
        self.assertIn(f"cache cache_{fe.id}", conf)
        self.assertIn("total-max-size 16", conf)
        self.assertIn("max-age 120", conf)

    def test_cache_enabled_adds_filter_and_http_directives(self):
        fe = self._make_frontend(mode="http", enable_cache=True)
        conf = self._generate(fe)
        self.assertIn(f"filter cache cache_{fe.id}", conf)
        self.assertIn(f"http-request cache-use cache_{fe.id}", conf)
        self.assertIn(f"http-response cache-store cache_{fe.id}", conf)

    def test_cache_disabled_no_cache_section(self):
        fe = self._make_frontend(mode="http", enable_cache=False)
        conf = self._generate(fe)
        self.assertNotIn("cache cache_", conf)
        self.assertNotIn("filter cache", conf)

    def test_cache_only_in_http_mode(self):
        """Le cache HAProxy n'existe qu'en mode HTTP"""
        fe = self._make_frontend(mode="tcp", enable_cache=True)
        conf = self._generate(fe)
        # En mode TCP, le bloc cache ne doit pas apparaitre
        self.assertNotIn("filter cache", conf)



class TestFrontendCompression(FrontendConfTestBase):
    """Compression HTTP"""

    def test_compression_enabled_adds_filter(self):
        fe = self._make_frontend(
            mode="http",
            enable_compression=True,
            compression_algos="gzip",
            compression_mime_types="text/html,text/plain",
        )
        conf = self._generate(fe)
        self.assertIn("filter compression", conf)
        self.assertIn("compression algo gzip", conf)
        self.assertIn("compression type text/html,text/plain", conf)

    def test_compression_disabled_no_filter(self):
        fe = self._make_frontend(mode="http", enable_compression=False)
        conf = self._generate(fe)
        self.assertNotIn("filter compression", conf)

    def test_compression_multiple_algos(self):
        fe = self._make_frontend(
            mode="http",
            enable_compression=True,
            compression_algos="gzip deflate",
        )
        conf = self._generate(fe)
        self.assertIn("compression algo gzip deflate", conf)

    def test_cache_and_compression_adds_htx(self):
        """Cache + compression ensemble -> HAProxy HTX proxy doit etre active"""
        fe = self._make_frontend(
            mode="http",
            enable_cache=True,
            enable_compression=True,
        )
        conf = self._generate(fe)
        self.assertIn("option http-use-htx", conf)



class TestFrontendLogModeHealthcheck(FrontendConfTestBase):
    """Mode LOG + healthcheck_service """

    def test_healthcheck_service_enabled_adds_tcp_check(self):
        fe = self._make_frontend(
            mode="log",
            listening_mode="tcp",
            healthcheck_service=True,
        )
        conf = self._generate(fe)
        self.assertIn("option tcp-check", conf)
        self.assertIn("tcp-check connect linger", conf)
        self.assertIn("tcp-request connection reject if { nbsrv() lt 1 }", conf)

    def test_healthcheck_service_disabled_no_tcp_check(self):
        fe = self._make_frontend(
            mode="log",
            listening_mode="tcp",
            healthcheck_service=False,
        )
        conf = self._generate(fe)
        self.assertNotIn("option tcp-check", conf)

    def test_healthcheck_adds_check_on_server_lines(self):
        """Avec healthcheck, les lignes 'server' doivent inclure les directives check"""
        from unittest.mock import MagicMock
        listener_mock = MagicMock()
        listener_mock.generate_conf.return_value = "bind 127.0.0.5:10001"
        listener_mock.generate_server_conf.return_value = "127.0.0.4:10001"

        fe = self._make_frontend(
            mode="log",
            listening_mode="tcp",
            healthcheck_service=True,
        )
        conf = self._generate(fe, listener_list=[listener_mock])
        self.assertIn("check inter 5s", conf)
        self.assertIn("observe layer4", conf)



class TestFrontendXForwardedProto(FrontendConfTestBase):
    """
    X-Forwarded-Proto (present par defaut en HTTP)
    """

    def test_http_mode_adds_x_forwarded_proto(self):
        """En mode HTTP, HAProxy doit injecter X-Forwarded-Proto"""
        fe = self._make_frontend(mode="http")
        conf = self._generate(fe)
        self.assertIn("X-Forwarded-Proto", conf)
        self.assertIn("ssl_fc", conf)

    def test_tcp_mode_no_x_forwarded_proto(self):
        fe = self._make_frontend(mode="tcp")
        conf = self._generate(fe)
        self.assertNotIn("X-Forwarded-Proto", conf)



class TestFrontendWithListeners(FrontendConfTestBase):
    """
    Teste generate_conf() quand des listeners reels sont injectes.
    On mocke generate_conf() du listener pour rester unitaire.
    """

    def _make_listener_mock(self, addr_port="127.0.0.5:443", server_conf="127.0.0.4:10001"):
        m = MagicMock()
        m.generate_conf.return_value = f"bind {addr_port}"
        m.generate_server_conf.return_value = server_conf
        return m

    def test_single_listener_bind_appears_in_conf(self):
        listener = self._make_listener_mock("127.0.0.5:443")
        fe = self._make_frontend(mode="http")
        conf = self._generate(fe, listener_list=[listener])
        self.assertIn("bind 127.0.0.5:443", conf)

    def test_multiple_listeners_all_appear(self):
        l1 = self._make_listener_mock("127.0.0.5:80")
        l2 = self._make_listener_mock("127.0.0.5:443")
        fe = self._make_frontend(mode="http")
        conf = self._generate(fe, listener_list=[l1, l2])
        self.assertIn("bind 127.0.0.5:80", conf)
        self.assertIn("bind 127.0.0.5:443", conf)

    def test_no_listener_no_bind_line(self):
        fe = self._make_frontend(mode="http")
        conf = self._generate(fe, listener_list=[])
        self.assertNotIn("bind ", conf)

    def test_log_mode_generates_server_lines_from_listeners(self):
        """En mode log, les listeners deviennent des lignes 'server'"""
        listener = self._make_listener_mock(server_conf="127.0.0.4:10001")
        fe = self._make_frontend(mode="log", listening_mode="tcp", name="log-fe")
        conf = self._generate(fe, listener_list=[listener])
        self.assertIn("server server_log-fe-1 127.0.0.4:10001", conf)

    def test_log_mode_multiple_listeners_multiple_server_lines(self):
        l1 = self._make_listener_mock(server_conf="127.0.0.4:10001")
        l2 = self._make_listener_mock(server_conf="127.0.0.4:10002")
        fe = self._make_frontend(mode="log", listening_mode="tcp", name="multi-log-fe")
        conf = self._generate(fe, listener_list=[l1, l2])
        self.assertIn("server server_multi-log-fe-1 127.0.0.4:10001", conf)
        self.assertIn("server server_multi-log-fe-2 127.0.0.4:10002", conf)



class TestFrontendWithWorkflows(FrontendConfTestBase):
    """
    Verifie la generation de la section WORKFLOWS dans la conf HAProxy
    On patche workflow_set pour ne pas creer de vrais objets Workflow/Backend
    """

    def _make_workflow_mock(self, wf_id=1, name="test-wf", fqdn="app.example.com",
                             public_dir="/", mode="http", backend_name="my-backend",
                             timeout_connect=2000, timeout_server=30,
                             enable_cors_policy=False, cors_allowed_methods=None,
                             cors_allowed_origins="*", cors_allowed_headers="*",
                             cors_max_age=86400):
        return {
            "id": wf_id,
            "name": name,
            "fqdn": fqdn,
            "public_dir": public_dir,
            "mode": mode,
            "backend_name": backend_name,
            "timeout_connect": timeout_connect,
            "timeout_server": timeout_server,
            "enable_cors_policy": enable_cors_policy,
            "cors_allowed_methods": cors_allowed_methods or ["GET", "POST"],
            "cors_allowed_origins": cors_allowed_origins,
            "cors_allowed_headers": cors_allowed_headers,
            "cors_max_age": cors_max_age,
        }

    def _generate_with_workflows(self, workflows, mode="http", **fe_kwargs):
        fe = self._make_frontend(mode=mode, **fe_kwargs)
        # Patch workflow_set pour retourner nos mocks
        with patch.object(fe, "workflow_set") as mock_ws:
            mock_ws.filter.return_value = [
                type("W", (), w)() for w in workflows
            ]
            return fe.generate_conf(listener_list=[], header_list=[])

    def test_workflow_creates_acl_for_fqdn(self):
        wf = self._make_workflow_mock(wf_id=42, fqdn="api.example.com", public_dir="/api")
        conf = self._generate_with_workflows([wf])
        self.assertIn("acl workflow_42_host hdr(host) api.example.com", conf)

    def test_workflow_creates_acl_for_path(self):
        wf = self._make_workflow_mock(wf_id=42, fqdn="app.example.com", public_dir="/admin")
        conf = self._generate_with_workflows([wf])
        self.assertIn("acl workflow_42_dir path -i -m beg /admin", conf)

    def test_workflow_creates_use_backend_directive(self):
        wf = self._make_workflow_mock(wf_id=99, fqdn="app.example.com", public_dir="/")
        conf = self._generate_with_workflows([wf])
        self.assertIn("use_backend Workflow_99", conf)

    def test_workflow_creates_backend_section(self):
        wf = self._make_workflow_mock(wf_id=7, backend_name="srv-backend",
                                       timeout_connect=3000, timeout_server=60)
        conf = self._generate_with_workflows([wf])
        self.assertIn("backend Workflow_7", conf)
        self.assertIn("timeout connect 3000ms", conf)
        self.assertIn("timeout server 60s", conf)

    def test_https_redirect_inside_workflows_block(self):
        """https_redirect=True doit generer la redirection dans le bloc workflows"""
        wf = self._make_workflow_mock(wf_id=1)
        conf = self._generate_with_workflows([wf], https_redirect=True)
        self.assertIn("redirect scheme https code 301", conf)

    def test_multiple_workflows_ordered_by_path_depth(self):
        """
        Les workflows doivent etre tries par profondeur de chemin decroissante
        pour que les regles plus specifiques soient evaluees en premier.
        """
        wf_root = self._make_workflow_mock(wf_id=1, public_dir="/")
        wf_deep = self._make_workflow_mock(wf_id=2, public_dir="/api/v1/users")
        wf_mid = self._make_workflow_mock(wf_id=3, public_dir="/api")
        conf = self._generate_with_workflows([wf_root, wf_deep, wf_mid])
        pos_root = conf.find("use_backend Workflow_1")
        pos_mid = conf.find("use_backend Workflow_3")
        pos_deep = conf.find("use_backend Workflow_2")
        self.assertLess(pos_deep, pos_mid)
        self.assertLess(pos_mid, pos_root)

    def test_cors_policy_enabled_adds_lua_cors(self):
        wf = self._make_workflow_mock(
            wf_id=5,
            enable_cors_policy=True,
            cors_allowed_methods=["GET", "POST", "OPTIONS"],
        )
        conf = self._generate_with_workflows([wf])
        self.assertIn("http-request lua.cors", conf)
        self.assertIn("http-response lua.cors", conf)

    def test_cors_policy_disabled_no_lua_cors(self):
        wf = self._make_workflow_mock(wf_id=5, enable_cors_policy=False)
        conf = self._generate_with_workflows([wf])
        self.assertNotIn("lua.cors", conf)



class TestListenerGenerateConf(TestCase):
    """
    Teste Listener.generate_conf() independamment du Frontend.
    Cette methode produit la directive 'bind' d'HAProxy.
    """

    TEST_CASE_NAME = f"{__name__}_listener"

    def setUp(self):
        self.node = Node.objects.create(
            name=f"node_{self.TEST_CASE_NAME}",
            management_ip="10.0.0.1",
            internet_ip="1.2.3.4",
            backends_outgoing_ip="10.0.0.1",
            logom_outgoing_ip="10.0.0.1",
        )
        self.nic = NetworkInterfaceCard.objects.create(
            dev="vtnet0",
            node=self.node,
        )
        self.netaddr_v4 = NetworkAddress.objects.create(
            name=f"addr_v4_{self.TEST_CASE_NAME}",
            type="system",
            ip="192.168.1.10",
            prefix_or_netmask="24",
        )
        NetworkAddressNIC.objects.create(
            nic=self.nic,
            network_address=self.netaddr_v4,
        )
        self.tenants = Tenants.objects.create(name=f"tenants_{self.TEST_CASE_NAME}")
        self.frontend = Frontend.objects.create(
            name=f"fe_{self.TEST_CASE_NAME}",
            mode="http",
            tenants_config=self.tenants,
        )

    def test_listener_generate_conf_starts_with_bind(self):
        listener = Listener.objects.create(
            network_address=self.netaddr_v4,
            port=80,
            frontend=self.frontend,
        )
        conf = listener.generate_conf()
        self.assertTrue(conf.startswith("bind "))

    def test_listener_generate_conf_uses_haproxy_jail_address_v4(self):
        """
        HAProxy ecoute sur l'adresse de la jail HAProxy (127.0.0.5), pas
        sur l'adresse reseau reelle - c'est le fonctionnement par conception.
        """
        listener = Listener.objects.create(
            network_address=self.netaddr_v4,
            port=8080,
            frontend=self.frontend,
        )
        conf = listener.generate_conf()
        # L'adresse HAProxy jail inet est 127.0.0.5
        self.assertIn("127.0.0.5", conf)

    def test_listener_generate_conf_includes_rsyslog_port(self):
        listener = Listener.objects.create(
            network_address=self.netaddr_v4,
            port=443,
            frontend=self.frontend,
        )
        conf = listener.generate_conf()
        self.assertIn(str(listener.rsyslog_port), conf)

    def test_listener_no_tls_profiles_no_ssl_directive(self):
        listener = Listener.objects.create(
            network_address=self.netaddr_v4,
            port=80,
            frontend=self.frontend,
        )
        conf = listener.generate_conf()
        self.assertFalse(listener.is_tls)
        self.assertNotIn("ssl", conf)

    def test_listener_is_tls_false_without_profiles(self):
        listener = Listener.objects.create(
            network_address=self.netaddr_v4,
            port=443,
            frontend=self.frontend,
        )
        self.assertFalse(listener.is_tls)

    def test_listener_generate_rsyslog_conf_uses_rsyslog_jail_address(self):
        """
        generate_rsyslog_conf() doit utiliser l'adresse rsyslog jail (127.0.0.4).
        """
        listener = Listener.objects.create(
            network_address=self.netaddr_v4,
            port=514,
            frontend=self.frontend,
        )
        conf = listener.generate_rsyslog_conf()
        self.assertIn("127.0.0.4", conf)
        self.assertIn(str(listener.rsyslog_port), conf)

    def test_listener_rsyslog_port_auto_increments(self):
        """Chaque nouveau Listener doit obtenir un rsyslog_port unique"""
        l1 = Listener.objects.create(
            network_address=self.netaddr_v4,
            port=80,
            frontend=self.frontend,
        )
        netaddr2 = NetworkAddress.objects.create(
            name=f"addr_v4_2_{self.TEST_CASE_NAME}",
            type="system",
            ip="192.168.1.11",
            prefix_or_netmask="24",
        )
        l2 = Listener.objects.create(
            network_address=netaddr2,
            port=443,
            frontend=self.frontend,
        )
        self.assertNotEqual(l1.rsyslog_port, l2.rsyslog_port)
        self.assertEqual(l2.rsyslog_port, l1.rsyslog_port + 1)

    def test_generate_server_conf_uses_rsyslog_jail_and_port(self):
        listener = Listener.objects.create(
            network_address=self.netaddr_v4,
            port=514,
            frontend=self.frontend,
        )
        conf = listener.generate_server_conf()
        self.assertIn("127.0.0.4", conf)
        self.assertIn(str(listener.rsyslog_port), conf)
