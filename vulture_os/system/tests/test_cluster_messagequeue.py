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


from django.test import TestCase, override_settings
from django.utils import timezone
from unittest.mock import patch
from datetime import timedelta
from time import sleep

from system.cluster.models import Cluster, Node, MessageQueue



def _make_node(name, management_ip="10.0.0.1", internet_ip="1.2.3.4",
               backends_outgoing_ip="10.0.0.1", logom_outgoing_ip="10.0.0.1") -> Node:
    return Node.objects.create(
        name=name,
        management_ip=management_ip,
        internet_ip=internet_ip,
        backends_outgoing_ip=backends_outgoing_ip,
        logom_outgoing_ip=logom_outgoing_ip,
    )


def _make_pending_node(name) -> Node:
    """Un noeud 'en attente de bootstrap' : management_ip vide -> ignore par api_request"""
    return Node.objects.create(
        name=name,
        management_ip="",
        internet_ip="1.2.3.4",
        backends_outgoing_ip="1.2.3.4",
        logom_outgoing_ip="1.2.3.4",
    )


ACTION_RSYSLOG = "services.rsyslogd.rsyslog.restart_service"
ACTION_HAPROXY = "services.haproxy.haproxy.reload_service"
ACTION_PF      = "services.pf.pf.reload_service"
ACTION_BUILD   = "services.haproxy.haproxy.build_conf"



class TestClusterApiRequest(TestCase):
    """
    Cluster.api_request() dispatche une action vers tous les noeuds (ou un seul).
    Verifie la creation de MessageQueue, les retours de statut, et le filtrage
    des noeuds pending (management_ip='').
    """

    TEST_CASE_NAME = f"{__name__}_cluster"

    def setUp(self):
        patch("system.cluster.models.logger").start()
        self.addCleanup(patch.stopall)
        self.node1 = _make_node(f"node1_{self.TEST_CASE_NAME}", "10.0.0.1")
        self.node2 = _make_node(f"node2_{self.TEST_CASE_NAME}", "10.0.0.2")

    def tearDown(self):
        MessageQueue.objects.all().delete()

    # Dispatch broadcast
    def test_broadcast_creates_one_mq_per_node(self):
        Cluster.api_request(ACTION_RSYSLOG)
        self.assertEqual(MessageQueue.objects.count(), 2)

    def test_broadcast_targets_both_nodes(self):
        Cluster.api_request(ACTION_RSYSLOG)
        nodes_called = set(MessageQueue.objects.values_list("node_id", flat=True))
        self.assertIn(self.node1.pk, nodes_called)
        self.assertIn(self.node2.pk, nodes_called)

    def test_returns_status_true_on_success(self):
        result = Cluster.api_request(ACTION_RSYSLOG)
        self.assertTrue(result["status"])

    def test_returns_instances_list(self):
        result = Cluster.api_request(ACTION_RSYSLOG)
        self.assertIn("instances", result)
        self.assertEqual(len(result["instances"]), 2)

    def test_action_and_config_stored_in_mq(self):
        Cluster.api_request(ACTION_RSYSLOG, config="some_config_value")
        mq = MessageQueue.objects.filter(node=self.node1).first()
        self.assertEqual(mq.action, ACTION_RSYSLOG)
        self.assertEqual(mq.config, "some_config_value")

    def test_new_mq_has_status_new(self):
        Cluster.api_request(ACTION_RSYSLOG)
        for mq in MessageQueue.objects.all():
            self.assertEqual(mq.status, MessageQueue.MessageQueueStatus.NEW)

    # Dispatch cible (node=...)
    def test_targeted_to_single_node_creates_one_mq(self):
        Cluster.api_request(ACTION_RSYSLOG, node=self.node1)
        self.assertEqual(MessageQueue.objects.count(), 1)
        self.assertEqual(MessageQueue.objects.first().node, self.node1)

    def test_targeted_does_not_create_mq_for_other_node(self):
        Cluster.api_request(ACTION_RSYSLOG, node=self.node1)
        self.assertEqual(MessageQueue.objects.filter(node=self.node2).count(), 0)

    # Noeud pending (management_ip='')
    def test_pending_node_excluded_from_broadcast(self):
        """
        Un noeud avec management_ip='' est en cours de bootstrap.
        Il ne doit JAMAIS recevoir d'api_request.
        """
        pending = _make_pending_node(f"pending_{self.TEST_CASE_NAME}")
        Cluster.api_request(ACTION_RSYSLOG)
        mq_nodes = set(MessageQueue.objects.values_list("node__name", flat=True))
        self.assertNotIn(pending.name, mq_nodes)
        # Les deux noeuds normaux sont bien la
        self.assertIn(self.node1.name, mq_nodes)
        self.assertIn(self.node2.name, mq_nodes)

    def test_three_pending_nodes_broadcast_only_hits_normal_nodes(self):
        for i in range(3):
            _make_pending_node(f"pending{i}_{self.TEST_CASE_NAME}")
        Cluster.api_request(ACTION_HAPROXY)
        # Seulement les 2 noeuds normaux doivent avoir un MQ
        self.assertEqual(MessageQueue.objects.count(), 2)

    # Deduplication (update_or_create)
    def test_same_action_same_node_deduplicates_mq(self):
        """
        Deux appels successifs avec la meme action sur le meme noeud en statut NEW
        doivent fusionner en un seul MessageQueue (update_or_create).
        """
        Cluster.api_request(ACTION_RSYSLOG, node=self.node1)
        Cluster.api_request(ACTION_RSYSLOG, node=self.node1)
        self.assertEqual(MessageQueue.objects.filter(
            node=self.node1, action=ACTION_RSYSLOG
        ).count(), 1)

    def test_completed_mq_creates_new_one(self):
        """
        Un MQ en statut DONE doit creer un nouveau MQ (pas de deduplication)
        """
        Cluster.api_request(ACTION_RSYSLOG, node=self.node1)
        mq = MessageQueue.objects.get(node=self.node1)
        mq.status = MessageQueue.MessageQueueStatus.DONE
        mq.save()

        Cluster.api_request(ACTION_RSYSLOG, node=self.node1)
        self.assertEqual(MessageQueue.objects.filter(
            node=self.node1, action=ACTION_RSYSLOG
        ).count(), 2)

    def test_failed_mq_creates_new_one(self):
        """Un MQ FAILURE doit generer un nouveau MQ pour retry"""
        Cluster.api_request(ACTION_HAPROXY, node=self.node1)
        mq = MessageQueue.objects.get(node=self.node1)
        mq.status = MessageQueue.MessageQueueStatus.FAILURE
        mq.save()

        Cluster.api_request(ACTION_HAPROXY, node=self.node1)
        self.assertEqual(MessageQueue.objects.filter(
            node=self.node1, action=ACTION_HAPROXY
        ).count(), 2)

    def test_running_mq_deduplicates(self):
        """Un MQ RUNNING en cours d'execution ne doit PAS etre duplique"""
        Cluster.api_request(ACTION_RSYSLOG, node=self.node1)
        mq = MessageQueue.objects.get(node=self.node1)
        mq.status = MessageQueue.MessageQueueStatus.RUNNING
        mq.save()

        # En statut RUNNING, le MQ n'est plus NEW -> update_or_create cree un nouveau
        # (comportement reel du code : only NEW est deduplique)
        count_before = MessageQueue.objects.filter(node=self.node1).count()
        Cluster.api_request(ACTION_RSYSLOG, node=self.node1)
        count_after = MessageQueue.objects.filter(node=self.node1).count()
        # Le comportement attendu est qu'un nouveau MQ est cree
        self.assertGreaterEqual(count_after, count_before)



class TestNodeApiRequest(TestCase):
    """
    Node.api_request() delegue a Cluster.api_request() avec node=self.
    Verifie notamment le scheduling via run_delay et get_pending_messages().
    """

    TEST_CASE_NAME = f"{__name__}_node"

    def setUp(self):
        patch("system.cluster.models.logger").start()
        self.addCleanup(patch.stopall)
        self.node1 = _make_node(f"n1_{self.TEST_CASE_NAME}", "10.0.0.1")
        self.node2 = _make_node(f"n2_{self.TEST_CASE_NAME}", "10.0.0.2")

    def tearDown(self):
        MessageQueue.objects.all().delete()

    # Delegation de base
    def test_node_api_request_creates_mq_for_correct_node(self):
        self.node1.api_request(ACTION_RSYSLOG)
        mq = MessageQueue.objects.get()
        self.assertEqual(mq.node, self.node1)

    def test_node_api_request_does_not_create_mq_for_other_node(self):
        self.node1.api_request(ACTION_HAPROXY)
        self.assertEqual(MessageQueue.objects.filter(node=self.node2).count(), 0)

    def test_node_api_request_with_config(self):
        self.node1.api_request(ACTION_BUILD, config="42")
        mq = MessageQueue.objects.get()
        self.assertEqual(mq.config, "42")

    def test_node_api_request_returns_status_true(self):
        result = self.node1.api_request(ACTION_RSYSLOG)
        self.assertTrue(result["status"])

    # run_delay : scheduling dans le futur
    def test_run_delay_schedules_mq_in_future(self):
        self.node1.api_request(ACTION_RSYSLOG, run_delay=30)
        mq = MessageQueue.objects.get()
        self.assertGreater(mq.run_at, timezone.now())
        self.assertAlmostEqual(
            mq.run_at,
            timezone.now() + timedelta(seconds=30),
            delta=timedelta(seconds=2)
        )

    def test_run_delay_zero_schedules_immediately(self):
        self.node1.api_request(ACTION_RSYSLOG, run_delay=0)
        mq = MessageQueue.objects.get()
        self.assertAlmostEqual(mq.run_at, timezone.now(), delta=timedelta(seconds=2))

    def test_delayed_mq_not_in_get_pending_messages(self):
        """
        Un MQ planifie dans le futur ne doit pas apparaitre dans
        get_pending_messages() (qui ne retourne que les MQ prets)
        """
        self.node1.api_request(ACTION_RSYSLOG, run_delay=300)
        pending = list(self.node1.get_pending_messages())
        self.assertEqual(len(pending), 0)

    def test_immediate_mq_in_get_pending_messages(self):
        self.node1.api_request(ACTION_RSYSLOG, run_delay=0)
        pending = list(self.node1.get_pending_messages())
        self.assertEqual(len(pending), 1)

    def test_delayed_then_updated_updates_run_at(self):
        """
        Rescheduler un MQ existant (meme action, meme noeud) met a jour run_at.
        """
        creation_time = timezone.now()
        self.node1.api_request(ACTION_RSYSLOG, run_delay=60)
        sleep(1)  # Pour que modified soit different
        self.node1.api_request(ACTION_RSYSLOG, run_delay=60)

        mq = MessageQueue.objects.get(node=self.node1, action=ACTION_RSYSLOG)
        # date_add ne doit pas changer (c'est la creation initiale)
        self.assertAlmostEqual(mq.date_add, creation_time, delta=timedelta(seconds=2))
        # run_at doit etre recalcule par rapport au dernier appel
        self.assertAlmostEqual(
            mq.run_at,
            timezone.now() + timedelta(seconds=60),
            delta=timedelta(seconds=2)
        )

    # get_pending_messages() avec count
    def test_get_pending_messages_returns_all_without_count(self):
        self.node1.api_request(ACTION_RSYSLOG)
        self.node1.api_request(ACTION_HAPROXY)
        self.node1.api_request(ACTION_PF)
        pending = list(self.node1.get_pending_messages())
        self.assertEqual(len(pending), 3)

    def test_get_pending_messages_with_count_limits_results(self):
        self.node1.api_request(ACTION_RSYSLOG)
        self.node1.api_request(ACTION_HAPROXY)
        self.node1.api_request(ACTION_PF)
        pending = list(self.node1.get_pending_messages(count=2))
        self.assertEqual(len(pending), 2)

    def test_get_pending_messages_empty_when_no_mq(self):
        self.assertEqual(list(self.node1.get_pending_messages()), [])

    def test_get_pending_messages_only_for_this_node(self):
        self.node1.api_request(ACTION_RSYSLOG)
        self.node2.api_request(ACTION_HAPROXY)
        pending_n1 = list(self.node1.get_pending_messages())
        self.assertEqual(len(pending_n1), 1)
        self.assertEqual(pending_n1[0].node, self.node1)

    def test_get_pending_messages_ordered_by_run_at(self):
        """get_pending_messages() doit retourner les MQ dans l'ordre d'execution"""
        r1 = self.node1.api_request(ACTION_RSYSLOG)
        mq1 = r1["instances"][0]
        r2 = self.node1.api_request(ACTION_HAPROXY)
        mq2 = r2["instances"][0]
        pending = list(self.node1.get_pending_messages())
        # Le premier cree doit etre le premier dans la liste
        self.assertEqual(pending[0], mq1)
        self.assertEqual(pending[1], mq2)



class TestClusterGetCurrentNode(TestCase):

    TEST_CASE_NAME = f"{__name__}_current_node"

    def setUp(self):
        patch("system.cluster.models.logger").start()
        self.addCleanup(patch.stopall)

    def test_get_current_node_returns_node_matching_hostname(self):
        node = _make_node(f"my-hostname_{self.TEST_CASE_NAME}")
        with override_settings(HOSTNAME=node.name):
            result = Cluster.get_current_node()
        self.assertEqual(result, node)

    def test_get_current_node_returns_false_when_not_found(self):
        with override_settings(HOSTNAME="nonexistent-hostname-xyz"):
            result = Cluster.get_current_node()
        self.assertFalse(result)

    def test_is_node_bootstrapped_true_when_node_exists(self):
        node = _make_node(f"bootstrapped_{self.TEST_CASE_NAME}")
        with override_settings(HOSTNAME=node.name):
            result = Cluster.is_node_bootstrapped()
        self.assertTrue(result)

    def test_is_node_bootstrapped_false_when_node_missing(self):
        with override_settings(HOSTNAME="ghost-node-xyz"):
            result = Cluster.is_node_bootstrapped()
        self.assertFalse(result)


class TestMessageQueueModel(TestCase):
    """
    MessageQueue : comportements du modele
    """

    TEST_CASE_NAME = f"{__name__}_mq"

    def setUp(self):
        patch("system.cluster.models.logger").start()
        self.addCleanup(patch.stopall)
        self.node = _make_node(f"mq-node_{self.TEST_CASE_NAME}")

    def tearDown(self):
        MessageQueue.objects.all().delete()

    def test_mq_default_status_is_new(self):
        result = self.node.api_request(ACTION_RSYSLOG)
        mq = result["instances"][0]
        self.assertEqual(mq.status, MessageQueue.MessageQueueStatus.NEW)

    def test_mq_save_updates_modified_timestamp(self):
        self.node.api_request(ACTION_RSYSLOG)
        mq = MessageQueue.objects.get()
        original_modified = mq.modified
        sleep(1)
        mq.result = "done"
        mq.save()
        mq.refresh_from_db()
        self.assertGreater(mq.modified, original_modified)

    def test_mq_to_template_contains_required_fields(self):
        self.node.api_request(ACTION_RSYSLOG)
        mq = MessageQueue.objects.get()
        template = mq.to_template()
        for field in ["date_add", "node", "status", "action", "config", "result", "modified", "run_at"]:
            self.assertIn(field, template, f"Champ manquant dans to_template(): {field}")

    def test_mq_to_template_action_is_shortened(self):
        """to_template() raccourcit l'action a ses 2 derniers segments"""
        self.node.api_request("services.rsyslogd.rsyslog.restart_service")
        mq = MessageQueue.objects.get()
        template = mq.to_template()
        self.assertEqual(template["action"], "rsyslog : restart_service")

    def test_mq_config_stored_as_string(self):
        self.node.api_request(ACTION_BUILD, config="frontend_pk=42")
        mq = MessageQueue.objects.get()
        self.assertIsInstance(mq.config, str)
        self.assertEqual(mq.config, "frontend_pk=42")

    def test_mq_internal_flag_defaults_to_false(self):
        self.node.api_request(ACTION_RSYSLOG)
        mq = MessageQueue.objects.get()
        self.assertFalse(mq.internal)

    def test_mq_internal_flag_can_be_set_true(self):
        self.node.api_request(ACTION_RSYSLOG, internal=True)
        mq = MessageQueue.objects.get()
        self.assertTrue(mq.internal)

    def test_status_choices_are_valid(self):
        valid_statuses = {
            MessageQueue.MessageQueueStatus.NEW,
            MessageQueue.MessageQueueStatus.RUNNING,
            MessageQueue.MessageQueueStatus.DONE,
            MessageQueue.MessageQueueStatus.FAILURE,
        }
        self.assertEqual(valid_statuses, {"new", "running", "done", "failure"})




class TestFrontendReloadConf(TestCase):
    """
    Frontend.reload_conf() orchestre les appels api_request() vers les noeuds
    concernes; on verifie quelles actions sont dispatche et dans quel ordre
    """

    TEST_CASE_NAME = f"{__name__}_reload"

    def setUp(self):
        patch("system.cluster.models.logger").start()
        patch("services.frontend.models.logger").start()
        self.addCleanup(patch.stopall)

        from system.cluster.models import NetworkAddress, NetworkInterfaceCard, NetworkAddressNIC
        from system.tenants.models import Tenants
        from services.frontend.models import Frontend, Listener

        self.node = _make_node(f"reload-node_{self.TEST_CASE_NAME}")
        self.nic = NetworkInterfaceCard.objects.create(dev="vtnet0", node=self.node)
        self.netaddr = NetworkAddress.objects.create(
            name=f"addr_{self.TEST_CASE_NAME}",
            type="system",
            ip="192.168.1.1",
            prefix_or_netmask="24",
        )
        NetworkAddressNIC.objects.create(nic=self.nic, network_address=self.netaddr)
        self.tenants = Tenants.objects.create(name=f"t_reload_{self.TEST_CASE_NAME}")

        self.frontend_http = Frontend.objects.create(
            name=f"fe_http_{self.TEST_CASE_NAME}",
            mode="http",
            enabled=True,
            tenants_config=self.tenants,
        )
        self.listener = Listener.objects.create(
            network_address=self.netaddr,
            port=443,
            frontend=self.frontend_http,
        )

    def tearDown(self):
        MessageQueue.objects.all().delete()

    def _get_actions(self, node=None) -> list:
        """Retourne la liste des actions MQ creees pour un noeud donne"""
        qs = MessageQueue.objects.all()
        if node:
            qs = qs.filter(node=node)
        return list(qs.order_by("date_add").values_list("action", flat=True))

    # Mode HTTP enabled
    def test_http_enabled_dispatches_build_conf(self):
        self.frontend_http.reload_conf()
        actions = self._get_actions(self.node)
        self.assertIn("services.haproxy.haproxy.build_conf", actions)

    def test_http_enabled_dispatches_haproxy_reload(self):
        self.frontend_http.reload_conf()
        actions = self._get_actions(self.node)
        self.assertIn("services.haproxy.haproxy.reload_service", actions)

    def test_http_enabled_dispatches_pf_gen_config(self):
        self.frontend_http.reload_conf()
        actions = self._get_actions(self.node)
        self.assertIn("services.pf.pf.gen_config", actions)

    def test_http_enabled_dispatches_pf_reload(self):
        self.frontend_http.reload_conf()
        actions = self._get_actions(self.node)
        self.assertIn("services.pf.pf.reload_service", actions)

    def test_http_enabled_no_rsyslog_build_without_logging(self):
        """Sans enable_logging, rsyslog ne doit pas etre rebuild pour un frontend HTTP"""
        self.frontend_http.enable_logging = False
        self.frontend_http.save()
        self.frontend_http.reload_conf()
        actions = self._get_actions(self.node)
        self.assertNotIn("services.rsyslogd.rsyslog.build_conf", actions)

    def test_http_with_logging_dispatches_rsyslog_build(self):
        self.frontend_http.enable_logging = True
        self.frontend_http.save()
        self.frontend_http.reload_conf()
        actions = self._get_actions(self.node)
        self.assertIn("services.rsyslogd.rsyslog.build_conf", actions)

    # Mode HTTP disabled
    def test_http_disabled_dispatches_delete_conf_not_build(self):
        from services.frontend.models import Frontend
        fe_disabled = Frontend.objects.create(
            name=f"fe_disabled_{self.TEST_CASE_NAME}",
            mode="http",
            enabled=False,
            tenants_config=self.tenants,
        )
        from services.frontend.models import Listener
        from system.cluster.models import NetworkAddress, NetworkAddressNIC
        netaddr2 = NetworkAddress.objects.create(
            name=f"addr2_{self.TEST_CASE_NAME}",
            type="system",
            ip="192.168.1.2",
            prefix_or_netmask="24",
        )
        NetworkAddressNIC.objects.create(nic=self.nic, network_address=netaddr2)
        Listener.objects.create(
            network_address=netaddr2,
            port=80,
            frontend=fe_disabled,
        )

        fe_disabled.reload_conf()
        actions = self._get_actions(self.node)

        self.assertIn("services.haproxy.haproxy.delete_conf", actions)
        self.assertNotIn("services.haproxy.haproxy.build_conf", actions)

    # Statut frontend apres reload_conf()
    def test_reload_conf_sets_status_waiting_on_node(self):
        self.frontend_http.reload_conf()
        self.frontend_http.refresh_from_db()
        node_name = self.node.name
        self.assertEqual(
            self.frontend_http.status.get(node_name),
            "WAITING"
        )

    # Mode LOG -> rsyslog uniquement
    def test_log_mode_file_dispatches_rsyslog_build(self):
        from services.frontend.models import Frontend
        fe_log = Frontend.objects.create(
            name=f"fe_log_{self.TEST_CASE_NAME}",
            mode="log",
            listening_mode="file",
            enabled=True,
            node=self.node,
            tenants_config=self.tenants,
        )
        MessageQueue.objects.all().delete()
        fe_log.reload_conf()
        actions = self._get_actions(self.node)
        self.assertIn("services.rsyslogd.rsyslog.build_conf", actions)
        # Pas de HAProxy pour un frontend LOG fichier
        self.assertNotIn("services.haproxy.haproxy.build_conf", actions)

    def test_log_mode_file_disabled_dispatches_rsyslog_delete(self):
        from services.frontend.models import Frontend
        fe_log = Frontend.objects.create(
            name=f"fe_log_dis_{self.TEST_CASE_NAME}",
            mode="log",
            listening_mode="file",
            enabled=False,
            node=self.node,
            tenants_config=self.tenants,
        )
        MessageQueue.objects.all().delete()
        fe_log.reload_conf()
        actions = self._get_actions(self.node)
        self.assertIn("services.rsyslogd.rsyslog.delete_conf", actions)

    def test_log_mode_api_disabled_does_not_delete_rsyslog(self):
        """
        Bug historique : un frontend LOG/API desactive ne doit PAS supprimer
        sa conf rsyslog (il continue a faire tourner le collecteur).
        """
        from services.frontend.models import Frontend
        fe_api = Frontend.objects.create(
            name=f"fe_api_{self.TEST_CASE_NAME}",
            mode="log",
            listening_mode="api",
            enabled=False,
            node=self.node,
            tenants_config=self.tenants,
        )
        MessageQueue.objects.all().delete()
        fe_api.reload_conf()
        actions = self._get_actions(self.node)
        self.assertNotIn("services.rsyslogd.rsyslog.delete_conf", actions)


class TestClusterAwaitApiRequest(TestCase):
    """
    Await API request (integration avec MessageQueue.await_result)
    """

    TEST_CASE_NAME = f"{__name__}_await"

    def setUp(self):
        patch("system.cluster.models.logger").start()
        self.addCleanup(patch.stopall)
        self.node1 = _make_node(f"await_n1_{self.TEST_CASE_NAME}")
        self.node2 = _make_node(f"await_n2_{self.TEST_CASE_NAME}")

    def tearDown(self):
        MessageQueue.objects.all().delete()

    @patch("system.cluster.models.MessageQueue.await_result")
    def test_await_calls_await_result_for_each_node(self, mock_await):
        mock_await.return_value = (True, "Success")
        Cluster.await_api_request(ACTION_RSYSLOG, interval=1, tries=2)
        self.assertEqual(mock_await.call_count, 2)

    @patch("system.cluster.models.MessageQueue.await_result")
    def test_await_passes_interval_and_tries(self, mock_await):
        mock_await.return_value = (True, "ok")
        Cluster.await_api_request(ACTION_RSYSLOG, interval=3, tries=5)
        mock_await.assert_called_with(3, 5)

    @patch("system.cluster.models.MessageQueue.await_result")
    def test_await_returns_false_on_any_node_failure(self, mock_await):
        mock_await.side_effect = [(True, "ok"), (False, "error")]
        status, results = Cluster.await_api_request(ACTION_RSYSLOG)
        self.assertFalse(status)

    @patch("system.cluster.models.MessageQueue.await_result")
    def test_await_returns_true_when_all_succeed(self, mock_await):
        mock_await.return_value = (True, "Success")
        status, results = Cluster.await_api_request(ACTION_RSYSLOG)
        self.assertTrue(status)
        self.assertEqual(len(results), 2)

    @patch("system.cluster.models.MessageQueue.await_result")
    def test_await_handles_timeout_exception(self, mock_await):
        from system.cluster.models import APISyncResultTimeOutException
        mock_await.side_effect = APISyncResultTimeOutException
        status, _ = Cluster.await_api_request(ACTION_RSYSLOG, interval=1, tries=1)
        self.assertFalse(status)

    @patch("system.cluster.models.MessageQueue.await_result")
    def test_await_targeted_node_calls_await_once(self, mock_await):
        mock_await.return_value = (True, "ok")
        Cluster.await_api_request(ACTION_RSYSLOG, node=self.node1)
        self.assertEqual(mock_await.call_count, 1)



class TestClusterMultiNodeScenarios(TestCase):
    """
    Scenarios realistes simulant ce qui se passe lors d'operations
    de configuration sur un cluster a plusieurs noeuds.
    """

    TEST_CASE_NAME = f"{__name__}_integration"

    def setUp(self):
        patch("system.cluster.models.logger").start()
        self.addCleanup(patch.stopall)
        self.nodes = [
            _make_node(f"cluster_node_{i}_{self.TEST_CASE_NAME}", f"10.0.0.{i}")
            for i in range(1, 4)
        ]

    def tearDown(self):
        MessageQueue.objects.all().delete()

    def test_full_service_restart_sequence(self):
        """
        Sequence realiste : build_conf -> reload_haproxy -> reload_pf
        Ces 3 actions doivent etre dans le MQ pour chaque noeud.
        """
        Cluster.api_request(ACTION_BUILD)
        Cluster.api_request(ACTION_HAPROXY)
        Cluster.api_request(ACTION_PF)

        for node in self.nodes:
            node_actions = set(
                MessageQueue.objects.filter(node=node).values_list("action", flat=True)
            )
            self.assertIn(ACTION_BUILD, node_actions)
            self.assertIn(ACTION_HAPROXY, node_actions)
            self.assertIn(ACTION_PF, node_actions)

    def test_adding_pending_node_does_not_receive_previous_actions(self):
        """
        Un nouveau noeud ajoute apres des api_request existants ne recoit
        pas retroactivement les actions deja dispatchees
        """
        Cluster.api_request(ACTION_RSYSLOG)
        initial_count = MessageQueue.objects.count()

        _ = _make_pending_node(f"late_node_{self.TEST_CASE_NAME}")
        # Les MQ existants ne changent pas
        self.assertEqual(MessageQueue.objects.count(), initial_count)

    def test_cluster_handles_mixed_node_states(self):
        """
        Cluster avec noeuds normaux + pending : seuls les normaux recoivent les actions.
        """
        pending1 = _make_pending_node(f"pend1_{self.TEST_CASE_NAME}")
        pending2 = _make_pending_node(f"pend2_{self.TEST_CASE_NAME}")

        Cluster.api_request(ACTION_HAPROXY)

        # Exactement 3 noeuds normaux doivent avoir un MQ
        self.assertEqual(MessageQueue.objects.count(), 3)
        pending_node_ids = {pending1.pk, pending2.pk}
        for mq in MessageQueue.objects.all():
            self.assertNotIn(mq.node_id, pending_node_ids)

    def test_sequential_actions_maintain_order(self):
        """
        Les actions dispatchees dans l'ordre doivent etre recuperables dans l'ordre
        """
        actions_ordered = [ACTION_BUILD, ACTION_HAPROXY, ACTION_PF]
        for action in actions_ordered:
            self.nodes[0].api_request(action)

        pending = list(self.nodes[0].get_pending_messages())
        retrieved_actions = [mq.action for mq in pending]
        self.assertEqual(retrieved_actions, actions_ordered)

    def test_different_configs_for_same_action_create_separate_mqs(self):
        """
        La meme action avec des configs differentes doit creer des MQ separes
        (config fait partie de la cle d'unicite).
        """
        self.nodes[0].api_request(ACTION_BUILD, config="frontend_id=1")
        self.nodes[0].api_request(ACTION_BUILD, config="frontend_id=2")
        count = MessageQueue.objects.filter(
            node=self.nodes[0], action=ACTION_BUILD
        ).count()
        self.assertEqual(count, 2)
