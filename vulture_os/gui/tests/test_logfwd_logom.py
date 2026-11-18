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


from django.test import TestCase
from unittest.mock import patch, MagicMock

from applications.logfwd.models import LogOM, LogOMFWD, LogOMFile, LogOMElasticSearch, LogOMHIREDIS
from system.tenants.models import Tenants
from services.frontend.models import Frontend


# Utils
# def _make_tenants(suffix="default"):
#     return Tenants.objects.get_or_create(name=f"tenants_logfwd_{suffix}")[0]

# def _make_frontend(name, log_condition="", tenants=None, **kwargs):
#     t = tenants or _make_tenants(name)
#     return Frontend.objects.create(
#         name=name,
#         mode="log",
#         listening_mode="file",
#         tenants_config=t,
#         log_condition=log_condition,
#         **kwargs,
#     )


class TestLogOMFWDConfGeneration(TestCase):
    TEST_CASE_NAME = f"{__name__}_fwd"

    def setUp(self):
        patch("applications.logfwd.models.logger").start()
        self.addCleanup(patch.stopall)

    def _fwd(self, **kwargs) -> LogOMFWD:
        defaults = dict(
            name=f"fwd_{id(kwargs)}",
            target="10.0.0.10",
            port=514,
            protocol="tcp",
            zip_level=0,
            enabled=True,
        )
        defaults.update(kwargs)
        return LogOMFWD.objects.create(**defaults)

    def _conf(self, logom: LogOMFWD, ruleset="test_ruleset") -> str:
        return LogOM.generate_conf(logom, ruleset, frontend="test_frontend")

    # Protocoles
    def test_tcp_protocol_in_conf(self):
        fwd = self._fwd(protocol="tcp")
        conf = self._conf(fwd)
        self.assertIn('Protocol="tcp"', conf)

    def test_udp_protocol_in_conf(self):
        fwd = self._fwd(protocol="udp")
        conf = self._conf(fwd)
        self.assertIn('Protocol="udp"', conf)

    def test_target_appears_in_conf(self):
        fwd = self._fwd(target="192.168.42.100")
        conf = self._conf(fwd)
        self.assertIn('Target="192.168.42.100"', conf)

    def test_port_appears_in_conf(self):
        fwd = self._fwd(port=6514)
        conf = self._conf(fwd)
        self.assertIn('Port="6514"', conf)

    def test_action_type_is_omfwd(self):
        fwd = self._fwd()
        conf = self._conf(fwd)
        self.assertIn('type="omfwd"', conf)


    # Compression
    def test_zip_level_zero_renders_as_zero(self):
        fwd = self._fwd(zip_level=0)
        conf = self._conf(fwd)
        self.assertIn('ZipLevel="0"', conf)

    def test_zip_level_nonzero_renders_correctly(self):
        fwd = self._fwd(zip_level=6)
        conf = self._conf(fwd)
        self.assertIn('ZipLevel="6"', conf)

    def test_zip_level_max_9(self):
        fwd = self._fwd(zip_level=9)
        conf = self._conf(fwd)
        self.assertIn('ZipLevel="9"', conf)


    # Rate limiting
    def test_no_ratelimit_no_interval_directive(self):
        fwd = self._fwd(ratelimit_interval=None, ratelimit_burst=None)
        conf = self._conf(fwd)
        self.assertNotIn("RateLimit.Interval", conf)
        self.assertNotIn("RateLimit.Burst", conf)

    def test_ratelimit_interval_appears_when_set(self):
        fwd = self._fwd(ratelimit_interval=60, ratelimit_burst=1000)
        conf = self._conf(fwd)
        self.assertIn('RateLimit.Interval="60"', conf)
        self.assertIn('RateLimit.Burst="1000"', conf)

    # Send as raw
    def test_send_as_raw_uses_raw_message_template(self):
        fwd = self._fwd(send_as_raw=True)
        conf = self._conf(fwd)
        self.assertIn('Template="raw_message"', conf)

    def test_send_as_raw_false_uses_ruleset_template(self):
        fwd = self._fwd(send_as_raw=False)
        conf = self._conf(fwd, ruleset="my_ruleset")
        self.assertIn('Template="my_ruleset"', conf)


    # Queue
    def test_queue_size_in_conf(self):
        fwd = self._fwd(queue_size=5000)
        conf = self._conf(fwd)
        self.assertIn('queue.size="5000"', conf)

    def test_dequeue_size_in_conf(self):
        fwd = self._fwd(dequeue_size=150)
        conf = self._conf(fwd)
        self.assertIn('queue.dequeuebatchsize="150"', conf)

    # Retry + DA queue
    def test_no_retry_no_resume_retry_count(self):
        fwd = self._fwd(enable_retry=False)
        conf = self._conf(fwd)
        self.assertNotIn("action.ResumeRetryCount", conf)

    def test_retry_enabled_adds_resume_retry_count(self):
        fwd = self._fwd(enable_retry=True)
        conf = self._conf(fwd)
        self.assertIn('action.ResumeRetryCount = "-1"', conf)

    def test_disk_assist_requires_retry(self):
        fwd = self._fwd(enable_retry=False, enable_disk_assist=True)
        conf = self._conf(fwd)
        self.assertNotIn("queue.highWatermark", conf)

    def test_disk_assist_with_retry_adds_watermarks(self):
        fwd = self._fwd(
            enable_retry=True,
            enable_disk_assist=True,
            high_watermark=9000,
            low_watermark=7000,
            spool_directory="/var/spool/rsyslog",
        )
        conf = self._conf(fwd)
        self.assertIn('queue.highWatermark="9000"', conf)
        self.assertIn('queue.lowWatermark="7000"', conf)
        self.assertIn('queue.spoolDirectory="/var/spool/rsyslog"', conf)
        self.assertIn('queue.saveOnShutdown="on"', conf)

    def test_output_name_contains_frontend_name(self):
        fwd = self._fwd(name="my-forwarder")
        conf = self._conf(fwd, ruleset="r")
        self.assertIn("my-forwarder_test_frontend", conf)



class TestLogOMFileConfGeneration(TestCase):
    """
    Template dynamique dans le nom de fichier via Django Template
    """
    def setUp(self):
        patch("applications.logfwd.models.logger").start()
        patch("applications.logfwd.models.Frontend.objects.filter", return_value=[]).start()
        self.addCleanup(patch.stopall)

    def _omfile(self, **kwargs) -> LogOMFile:
        defaults = dict(
            name=f"file_{id(kwargs)}",
            file="/var/log/vulture/{{ruleset}}.log",
            flush_interval=1,
            async_writing=True,
            retention_time=30,
            rotation_period="daily",
            enabled=True,
        )
        defaults.update(kwargs)
        return LogOMFile.objects.create(**defaults)

    def _conf(self, logom: LogOMFile, ruleset="haproxy") -> str:
        return LogOM.generate_conf(logom, ruleset, frontend="fe")

    def test_action_type_is_omfile(self):
        f = self._omfile()
        conf = self._conf(f)
        self.assertIn('type="omfile"', conf)

    def test_async_writing_on(self):
        f = self._omfile(async_writing=True)
        conf = self._conf(f)
        self.assertIn("asyncWriting", conf)

    def test_async_writing_off(self):
        f = self._omfile(async_writing=False)
        conf = self._conf(f)
        # "off" doit apparaître pour asyncWriting
        self.assertIn('"off"', conf)

    def test_template_id_is_sha256_of_name_and_ruleset(self):
        import hashlib
        f = self._omfile(name="deterministic-file")
        ruleset = "my_ruleset"
        expected = hashlib.sha256(
            (ruleset + "deterministic-file").encode("utf-8")
        ).hexdigest()
        self.assertEqual(f.template_id(ruleset=ruleset), expected)

    def test_ruleset_interpolated_in_filename(self):
        f = self._omfile(file="/var/log/{{ruleset}}.log")
        conf = self._conf(f, ruleset="nginx")
        self.assertIn("/var/log/nginx.log", conf)

    def test_get_rsyslog_template_empty_when_no_frontends(self):
        f = self._omfile(name="orphan-file")
        self.assertEqual(f.get_rsyslog_template(), "")

    def test_flush_interval_in_conf(self):
        f = self._omfile(flush_interval=5)
        conf = self._conf(f)
        self.assertIn('"5"', conf)



class TestLogOMHIREDISConfGeneration(TestCase):
    """
    LogOMHIREDIS (omhiredis) -> om_hiredis.tpl
    Modes : queue, set, publish, stream. Cle dynamique. TLS.
    """

    def setUp(self):
        patch("applications.logfwd.models.logger").start()
        patch("applications.logfwd.models.Frontend.objects.filter", return_value=[]).start()
        self.addCleanup(patch.stopall)

    def _redis(self, **kwargs) -> LogOMHIREDIS:
        defaults = dict(
            name=f"redis_{id(kwargs)}",
            target="10.0.0.3",
            port=6379,
            mode="queue",
            key="vulture-logs",
            dynamic_key=False,
            pwd=None,
            enabled=True,
        )
        defaults.update(kwargs)
        return LogOMHIREDIS.objects.create(**defaults)

    def _conf(self, logom: LogOMHIREDIS, ruleset="haproxy") -> str:
        return LogOM.generate_conf(logom, ruleset, frontend="fe")

    def test_action_type_is_omhiredis(self):
        r = self._redis()
        conf = self._conf(r)
        self.assertIn('type="omhiredis"', conf)

    def test_server_and_port_in_conf(self):
        r = self._redis(target="172.16.0.1", port=6380)
        conf = self._conf(r)
        self.assertIn('server="172.16.0.1"', conf)
        self.assertIn('serverport="6380"', conf)

    def test_queue_mode_in_conf(self):
        r = self._redis(mode="queue")
        conf = self._conf(r)
        self.assertIn('mode="queue"', conf)

    def test_set_mode_in_conf(self):
        r = self._redis(mode="set")
        conf = self._conf(r)
        self.assertIn('mode="set"', conf)

    def test_publish_mode_in_conf(self):
        r = self._redis(mode="publish")
        conf = self._conf(r)
        self.assertIn('mode="publish"', conf)

    def test_static_key_uses_key_directive(self):
        r = self._redis(key="my-static-key", dynamic_key=False)
        conf = self._conf(r)
        self.assertIn('key="my-static-key"', conf)
        self.assertNotIn("DynaKey", conf)

    def test_dynamic_key_uses_dynakey_and_template_id(self):
        r = self._redis(key="{{ruleset}}-logs", dynamic_key=True)
        conf = self._conf(r, ruleset="nginx")
        self.assertIn('DynaKey="on"', conf)
        # La cle dans la conf est le template_id, pas la valeur brute
        self.assertIn(r.template_id(), conf)

    def test_password_included_when_set(self):
        r = self._redis(pwd="s3cr3t!")
        conf = self._conf(r)
        self.assertIn('ServerPassword="s3cr3t!"', conf)

    def test_no_password_no_server_password_directive(self):
        r = self._redis(pwd=None)
        conf = self._conf(r)
        self.assertNotIn("ServerPassword", conf)

    def test_queue_mode_rpush_option(self):
        r = self._redis(mode="queue", use_rpush=True)
        conf = self._conf(r)
        self.assertIn('Userpush="on"', conf)

    def test_queue_mode_lpush_default(self):
        r = self._redis(mode="queue", use_rpush=False)
        conf = self._conf(r)
        self.assertIn('Userpush="off"', conf)

    def test_set_mode_with_expire_key(self):
        r = self._redis(mode="set", expire_key=3600)
        conf = self._conf(r)
        self.assertIn('Expiration="3600"', conf)

    def test_get_rsyslog_template_with_dynamic_key(self):
        r = self._redis(name="dyn-redis", dynamic_key=True, key="{{ruleset}}")
        # Simule un frontend associe
        with patch("applications.logfwd.models.Frontend.objects.filter") as mock_filter:
            mock_qs = MagicMock()
            mock_qs.exists.return_value = True
            mock_filter.return_value = mock_qs
            tpl = r.get_rsyslog_template()
        self.assertIn(r.template_id(), tpl)
        self.assertIn("template(", tpl)

    def test_get_rsyslog_template_empty_without_dynamic_key(self):
        r = self._redis(dynamic_key=False)
        tpl = r.get_rsyslog_template()
        self.assertEqual(tpl, "")


# ─────────────────────────────────────────────────────────────────────────────

class TestLogOMElasticSearchConfGeneration(TestCase):
    """
    LogOMElasticSearch (omelasticsearch) -> om_elasticsearch.tpl
    Serveurs multiples, index pattern, auth, TLS.
    """

    def setUp(self):
        patch("applications.logfwd.models.logger").start()
        self.addCleanup(patch.stopall)

    def _els(self, **kwargs) -> LogOMElasticSearch:
        defaults = dict(
            name=f"els_{id(kwargs)}",
            servers='["https://els-1:9200"]',
            index_pattern=f"mylog-{id(kwargs)}-%$!timestamp:1:10%",
            uid=None,
            pwd=None,
            enabled=True,
        )
        defaults.update(kwargs)
        return LogOMElasticSearch.objects.create(**defaults)

    def _conf(self, logom: LogOMElasticSearch, ruleset="haproxy") -> str:
        return LogOM.generate_conf(logom, ruleset, frontend="fe")

    def test_action_type_is_omelasticsearch(self):
        e = self._els()
        conf = self._conf(e)
        self.assertIn('type="omelasticsearch"', conf)

    def test_single_server_in_conf(self):
        e = self._els(servers='["https://els-prod:9200"]')
        conf = self._conf(e)
        self.assertIn("els-prod", conf)

    def test_index_pattern_in_conf(self):
        e = self._els(index_pattern="vulture-logs-%$!timestamp:1:10%")
        conf = self._conf(e)
        self.assertIn("vulture-logs", conf)

    def test_uid_and_pwd_when_set(self):
        e = self._els(uid="elastic", pwd="changeme")
        conf = self._conf(e)
        self.assertIn("elastic", conf)
        self.assertIn("changeme", conf)

    def test_no_uid_no_auth_directives(self):
        e = self._els(uid=None, pwd=None)
        conf = self._conf(e)
        # Les directives d'auth ne doivent pas apparaitre
        self.assertNotIn("uid=", conf)

    def test_template_property_returns_correct_template(self):
        e = self._els()
        self.assertEqual(e.template, "om_elasticsearch.tpl")

    def test_template_id_is_sha256_of_name(self):
        import hashlib
        e = self._els(name="stable-els-name")
        expected = hashlib.sha256("stable-els-name".encode("utf-8")).hexdigest()
        self.assertEqual(e.template_id(), expected)


class TestLogOMRenameLogConditionPropagation(TestCase):
    """
    Bug historique documente dans le changelog :
    quand un LogOM est renomme via logfwd_edit(),
    tous les Frontends qui l'utilisent dans log_condition doivent etre mis à jour

    Pattern dans le code (logfwd/views.py) :
        frontend.log_condition = frontend.log_condition.replace(
            f"{{{{{log_om_old_name}}}}}", f"{{{{{log_om.name}}}}}"
        )

    Ces tests valident la logique de remplacement directement
    sur les instances de modeles
    """

    TEST_CASE_NAME = f"{__name__}_rename"

    def setUp(self):
        patch("applications.logfwd.models.logger").start()
        patch("services.frontend.models.logger").start()
        self.addCleanup(patch.stopall)
        self.tenants = Tenants.objects.create(name=f"t_{self.TEST_CASE_NAME}")

    def _fe(self, name, log_condition="", **kwargs):
        return Frontend.objects.create(
            name=name,
            mode="log",
            listening_mode="file",
            tenants_config=self.tenants,
            log_condition=log_condition,
            **kwargs,
        )

    def _simulate_rename(self, old_name: str, new_name: str):
        """
        Reproduit exactement la logique de propagation de logfwd_edit() :
        pour chaque frontend qui reference old_name dans log_condition,
        applique le replace
        """
        from services.frontend.models import Frontend as FE
        frontends = FE.objects.filter(log_condition__contains=f"{{{{{old_name}}}}}")
        for fe in frontends:
            fe.log_condition = fe.log_condition.replace(
                f"{{{{{old_name}}}}}",
                f"{{{{{new_name}}}}}",
            )
            fe.save()


    # Cas nominaux
    def test_rename_updates_single_frontend(self):
        fe = self._fe("fe-a", log_condition="if {{old-fwd}} then action")
        self._simulate_rename("old-fwd", "new-fwd")
        fe.refresh_from_db()
        self.assertNotIn("{{old-fwd}}", fe.log_condition)
        self.assertIn("{{new-fwd}}", fe.log_condition)

    def test_rename_updates_all_referencing_frontends(self):
        """Plusieurs frontends referencant le meme forwarder doivent tous etre mis a jour"""
        frontends = [
            self._fe(f"fe-multi-{i}", log_condition=f"{{{{shared-fwd}}}} action{i}")
            for i in range(5)
        ]
        self._simulate_rename("shared-fwd", "renamed-fwd")
        for fe in frontends:
            fe.refresh_from_db()
            self.assertNotIn("{{shared-fwd}}", fe.log_condition)
            self.assertIn("{{renamed-fwd}}", fe.log_condition)

    def test_rename_does_not_affect_unrelated_frontends(self):
        """Un frontend sans reference a LogOM renomme ne doit pas changer."""
        unrelated = self._fe("fe-unrelated", log_condition="{{other-fwd}} something")
        self._simulate_rename("target-fwd", "new-fwd")
        unrelated.refresh_from_db()
        self.assertEqual(unrelated.log_condition, "{{other-fwd}} something")

    def test_no_rename_no_change(self):
        """old_name == new_name -> aucune modification."""
        original = "if {{stable-fwd}} then action"
        fe = self._fe("fe-stable", log_condition=original)
        self._simulate_rename("stable-fwd", "stable-fwd")
        fe.refresh_from_db()
        self.assertEqual(fe.log_condition, original)

    # Cas exotiques
    def test_multiple_occurrences_in_same_condition_all_replaced(self):
        """Si le nom apparait plusieurs fois dans log_condition, tous sont remplaces"""
        fe = self._fe(
            "fe-multi-ref",
            log_condition="{{multi}} OR {{multi}} as backup"
        )
        self._simulate_rename("multi", "replaced")
        fe.refresh_from_db()
        self.assertNotIn("{{multi}}", fe.log_condition)
        self.assertEqual(fe.log_condition.count("{{replaced}}"), 2)

    def test_rename_with_hyphens_in_name(self):
        fe = self._fe("fe-hyphens", log_condition="filter {{fwd-v2-prod}} active")
        self._simulate_rename("fwd-v2-prod", "fwd-v3-prod")
        fe.refresh_from_db()
        self.assertIn("{{fwd-v3-prod}}", fe.log_condition)

    def test_rename_with_underscores_in_name(self):
        fe = self._fe("fe-underscores", log_condition="{{fwd_prod_01}} forward")
        self._simulate_rename("fwd_prod_01", "fwd_prod_02")
        fe.refresh_from_db()
        self.assertIn("{{fwd_prod_02}}", fe.log_condition)

    def test_rename_with_numbers_in_name(self):
        fe = self._fe("fe-numbers", log_condition="{{logom123}} action")
        self._simulate_rename("logom123", "logom456")
        fe.refresh_from_db()
        self.assertIn("{{logom456}}", fe.log_condition)

    def test_rename_does_not_match_partial_names(self):
        """
        '{{fwd}}' ne doit PAS etre remplace si on renomme '{{fwd-extended}}'
        Les doubles accolades delimitent exactement le nom
        """
        fe = self._fe("fe-partial", log_condition="{{fwd}} is not {{fwd-extended}}")
        self._simulate_rename("fwd-extended", "fwd-renamed")
        fe.refresh_from_db()
        # {{fwd}} ne doit pas avoir change
        self.assertIn("{{fwd}}", fe.log_condition)
        self.assertIn("{{fwd-renamed}}", fe.log_condition)

    def test_rename_multiline_log_condition(self):
        """log_condition peut etre multiligne"""
        condition = "if {{alpha-fwd}} then\n  call action1\nif {{alpha-fwd}} then\n  call action2"
        fe = self._fe("fe-multiline", log_condition=condition)
        self._simulate_rename("alpha-fwd", "beta-fwd")
        fe.refresh_from_db()
        self.assertNotIn("{{alpha-fwd}}", fe.log_condition)
        self.assertEqual(fe.log_condition.count("{{beta-fwd}}"), 2)

    def test_empty_log_condition_not_affected(self):
        """Un log_condition vide ne doit pas lever d'exception"""
        fe = self._fe("fe-empty-cond", log_condition="")
        self._simulate_rename("any-fwd", "new-fwd")
        fe.refresh_from_db()
        self.assertEqual(fe.log_condition, "")

    def test_log_condition_with_no_pattern_not_affected(self):
        """log_condition sans aucun {{}} ne doit pas être modifie"""
        original = "plain text condition no forwarder"
        fe = self._fe("fe-no-pattern", log_condition=original)
        self._simulate_rename("some-fwd", "other-fwd")
        fe.refresh_from_db()
        self.assertEqual(fe.log_condition, original)

    def test_log_condition_with_multiple_different_forwarders(self):
        """Seul le forwarder renomme doit etre modifie, pas les autres"""
        fe = self._fe(
            "fe-mixed",
            log_condition="{{fwd-a}} and {{fwd-b}} and {{fwd-a}}"
        )
        self._simulate_rename("fwd-a", "fwd-alpha")
        fe.refresh_from_db()
        self.assertNotIn("{{fwd-a}}", fe.log_condition)
        self.assertIn("{{fwd-b}}", fe.log_condition)  # inchange
        self.assertEqual(fe.log_condition.count("{{fwd-alpha}}"), 2)



class TestRenderLogCondition(TestCase):
    """
    Frontend.render_log_condition() resout les tokens {{name}} en conf rsyslog reelle
    C'est la methode qui construit la section rsyslog a partir du log_condition du frontend
    """

    TEST_CASE_NAME = f"{__name__}_render"

    def setUp(self):
        patch("applications.logfwd.models.logger").start()
        patch("services.frontend.models.logger").start()
        patch("services.frontend.models.Cluster.get_current_node").start()
        patch("services.frontend.models.Cluster.get_global_config").start()
        self.addCleanup(patch.stopall)
        self.tenants = Tenants.objects.create(name=f"t_{self.TEST_CASE_NAME}")

    def _fe(self, name, log_condition="", **kwargs):
        return Frontend.objects.create(
            name=name,
            mode="log",
            listening_mode="file",
            tenants_config=self.tenants,
            log_condition=log_condition,
            enable_logging=True,
            **kwargs,
        )

    def test_empty_log_condition_returns_newline(self):
        """log_condition="" -> resultat vide (juste un newline final)"""
        fe = self._fe("fe-empty-render")
        result = fe.render_log_condition()
        self.assertEqual(result.strip(), "")

    def test_log_condition_without_double_braces_passed_through(self):
        """Lignes sans {{ }} sont ignorees (ne contiennent pas de forwarder)"""
        fe = self._fe("fe-no-braces", log_condition="plain log condition\nno forwarder")
        result = fe.render_log_condition()
        # Pas d'erreur, resultat passe tel quel
        self.assertIsInstance(result, str)

    def test_log_condition_with_enabled_forwarder_resolves(self):
        """
        {{fwd-name}} doit etre remplace par la conf rsyslog du forwarder correspondant
        """
        fwd = LogOMFWD.objects.create(
            name=f"render-test-fwd-{self.TEST_CASE_NAME}",
            target="10.0.0.99",
            port=514,
            protocol="tcp",
            enabled=True,
        )
        fe = self._fe(
            "fe-render-resolved",
            log_condition=f"if 1==1 then {{{{{fwd.name}}}}}",
        )
        fe.log_forwarders.add(fwd)

        result = fe.render_log_condition()
        # La conf doit contenir quelque chose de rsyslog (type omfwd)
        self.assertIn('type="omfwd"', result)

    def test_log_condition_disabled_forwarder_excluded(self):
        """
        Un LogOM desactive (enabled=False) ne doit pas etre rendu
        dans le log_condition final
        """
        fwd = LogOMFWD.objects.create(
            name=f"disabled-fwd-{self.TEST_CASE_NAME}",
            target="10.0.0.50",
            port=514,
            protocol="tcp",
            enabled=False,
        )
        fe = self._fe(
            "fe-disabled-fwd",
            log_condition=f"if 1==1 then {{{{{fwd.name}}}}}",
        )
        fe.log_forwarders.add(fwd)

        result = fe.render_log_condition()
        # Le forwarder desactive ne doit pas generer d'action omfwd
        self.assertNotIn('type="omfwd"', result)



class TestLogOMSelectMethods(TestCase):
    """
    LogOM.select_log_om() et select_log_om_by_name() doivent retrouver
    la sous-classe a partir de l'ID ou du nom de la base abstraite
    """

    def setUp(self):
        patch("applications.logfwd.models.logger").start()
        self.addCleanup(patch.stopall)

    def test_select_log_om_by_id_returns_correct_subclass_fwd(self):
        fwd = LogOMFWD.objects.create(
            name="sel-fwd", target="1.2.3.4", port=514, protocol="tcp"
        )
        result = LogOM().select_log_om(fwd.pk)
        self.assertIsInstance(result, LogOMFWD)
        self.assertEqual(result.pk, fwd.pk)

    def test_select_log_om_by_id_returns_correct_subclass_file(self):
        f = LogOMFile.objects.create(
            name="sel-file", file="/var/log/test.log"
        )
        result = LogOM().select_log_om(f.pk)
        self.assertIsInstance(result, LogOMFile)
        self.assertEqual(result.pk, f.pk)

    def test_select_log_om_by_id_returns_correct_subclass_hiredis(self):
        r = LogOMHIREDIS.objects.create(
            name="sel-redis", target="127.0.0.1", port=6379, mode="queue", key="k"
        )
        result = LogOM().select_log_om(r.pk)
        self.assertIsInstance(result, LogOMHIREDIS)

    def test_select_log_om_nonexistent_raises(self):
        from django.core.exceptions import ObjectDoesNotExist
        with self.assertRaises(ObjectDoesNotExist):
            LogOM().select_log_om(99999999)

    def test_select_log_om_by_name_returns_correct_instance(self):
        _ = LogOMFWD.objects.create(
            name="by-name-fwd", target="1.2.3.4", port=514, protocol="tcp"
        )
        result = LogOM().select_log_om_by_name("by-name-fwd")
        self.assertIsInstance(result, LogOMFWD)
        self.assertEqual(result.name, "by-name-fwd")

    def test_select_log_om_by_name_nonexistent_raises(self):
        from django.core.exceptions import ObjectDoesNotExist
        with self.assertRaises(ObjectDoesNotExist):
            LogOM().select_log_om_by_name("this-name-does-not-exist-xyz")

    def test_template_id_is_sha256_of_name(self):
        import hashlib
        fwd = LogOMFWD.objects.create(
            name="deterministic", target="1.2.3.4", port=514, protocol="tcp"
        )
        expected = hashlib.sha256(b"deterministic").hexdigest()
        self.assertEqual(fwd.template_id(), expected)

    def test_template_id_different_names_different_hashes(self):
        fwd1 = LogOMFWD.objects.create(name="name-a", target="1.2.3.4", port=514, protocol="tcp")
        fwd2 = LogOMFWD.objects.create(name="name-b", target="1.2.3.4", port=515, protocol="tcp")
        self.assertNotEqual(fwd1.template_id(), fwd2.template_id())
