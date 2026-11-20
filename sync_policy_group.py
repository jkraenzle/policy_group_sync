# Python script for synchronizing Policy Groups (including groupCriteria / commonCriteria),
# Microtenant Default Groups (as Custom Policy Groups), and associated Rules (with policyCriteria)
# across Microtenants in Zscaler Private Access (ZPA)

# Requires:
# pip install requests pyyaml

import argparse
import copy
import ipaddress
import json
import logging as log
import logging.handlers
import os
import time
from datetime import date
from typing import Any, IO

import requests
import urllib3
import yaml

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ***** OneAPI & Related Classes *****

class OneAPI:
	"""
	Helper class to issue OneAPI requests to a Zscaler Private Access (ZPA) tenant,
	supporting Policy Group Sets, Policy Groups (groupCriteria / commonCriteria),
	and Policy Group Rules (policyCriteria), including automatic v1 (lhs/rhs) -> v2
	(values/entryValues) operand conversion on POST/PUT.
	"""

	APP_OBJECT_TYPES = {
		"APP",
		"APPLICATION",
		"APP_SEGMENT",
		"APPLICATION_SEGMENT",
		"SHARED_APP",
		"SHARED_APPLICATION",
		"MICROTENANT_APP",
	}

	# ZPA v2 operand objectTypes that require "values": ["..."]
	VALUES_OBJECT_TYPES = {
		"APP",
		"APP_GROUP",
		"CLIENT_TYPE",
		"EDGE_CONNECTOR_GROUP",
		"BRANCH_CONNECTOR_GROUP",
		"LOCATION",
		"MACHINE_GRP",
		"CHROME_POSTURE_PROFILE",
		"IDP",
		"WORKLOAD_TAG_GROUP",
		"CONSOLE",
		"PRIVILEGED_PORTAL",
		"USER_PORTAL",
	}

	# ZPA v2 operand objectTypes that require "entryValues": [{"lhs": "...", "rhs": "..."}]
	ENTRY_VALUES_OBJECT_TYPES = {
		"SAML",
		"SCIM",
		"SCIM_GROUP",
		"PLATFORM",
		"POSTURE",
		"TRUSTED_NETWORK",
		"COUNTRY_CODE",
		"RISK_FACTOR_TYPE",
		"CHROME_ENTERPRISE",
	}

	GROUP_CRITERIA_KEYS = (
		"groupCriteria",
		"commonCriteria",
		"policyGroupCriteria",
		"accessPolicyCriteria",
		"groupConditions",
		"commonConditions",
		"policyCriteria",
		"conditions",
		"criteria",
	)
	RULE_CRITERIA_KEYS = (
		"policyCriteria",
		"ruleCriteria",
		"conditions",
		"criteria",
	)
	ALL_CRITERIA_KEYS = (
		"groupCriteria",
		"commonCriteria",
		"policyGroupCriteria",
		"accessPolicyCriteria",
		"groupConditions",
		"commonConditions",
		"policyCriteria",
		"ruleCriteria",
		"conditions",
		"criteria",
	)

	DIRECT_APP_CONTAINER_KEYS = (
		"applications",
		"appSegments",
		"applicationSegments",
		"sharedApplicationSegments",
		"appSegmentIds",
		"applicationIds",
		"appIds",
	)

	EMBEDDED_RULE_COLLECTION_KEYS = {
		"rules",
		"policyRules",
		"accessRules",
		"ruleGids",
		"customRuleGids",
	}

	NON_APP_METADATA_KEYS = {
		"creationTime",
		"modifiedTime",
		"modifiedBy",
		"policySetId",
		"policyGroupSetId",
		"policyGroupSetGid",
		"policyGroupId",
		"policyGroupGid",
		"groupSetId",
		"groupId",
		"ruleId",
		"microtenantId",
		"microtenantName",
		"customerId",
		"idpId",
		"groupOrder",
		"ruleOrder",
		"order",
		"priority",
		"policyType",
		"permissionLevel",
	}

	CRITERIA_NODE_INDICATOR_KEYS = {
		"operands",
		"conditions",
		"criteria",
		"subCriteria",
		"groupCriteria",
		"commonCriteria",
		"policyGroupCriteria",
		"policyCriteria",
		"ruleCriteria",
		"expressions",
		"objectType",
		"criteriaType",
		"operandType",
		"lhs",
		"rhs",
		"value",
		"values",
		"rhsValue",
		"rhsValues",
		"entryValues",
		"operator",
		"negated",
	}

	def __init__(self, vanity_domain=None, client_id=None, client_secret=None, log=None, ssl_verify=False, readonly=False):
		if log is None:
			raise Exception("Logging subsystem failure")
		self.log = log

		if vanity_domain is None:
			raise Exception("Missing vanity domain")
		self.vanity_domain = vanity_domain

		if client_id is None or client_secret is None:
			raise Exception("Missing client ID or secret")
		self.client_id = client_id
		self.client_secret = client_secret

		self.class_name = "OneAPI"
		self.log.info(f"[{self.class_name}] Initializing ...")

		self.oneapi_base_fqdn = "api.zsapi.net"
		self.oneapi_zpa_endpoint = "/zpa"
		self.oneapi_zpa_mgmtv1_endpoint = "/zpa/mgmtconfig/v1"
		self.oneapi_zpa_mgmtv2_endpoint = "/zpa/mgmtconfig/v2"
		self.scim_base_url = "/zpa/userconfig/v1"
		self.session = None
		self.ssl_verify = ssl_verify
		self.readonly = readonly

		self.oneapi_zpa_customer_id = None
		self.oneapi_zpa_customer_name = None
		self.oneapi_zpa_microtenant_default_id = None
		self.oneapi_zpa_microtenant_default_name = None
		self.oneapi_zpa_microtenants = None
		self.headers = {
			"Content-Type": "application/json",
			"Cache-Control": "no-cache",
			"User-Agent": "Zscaler Python/REST API Connector",
		}

	# ***** Authenticate *****

	def authenticate(self):
		self.log.info(f"[{self.class_name}] Authenticating ...")
		try:
			uri = f"https://{self.vanity_domain}.zslogin.net/oauth2/v1/token"
			payload = {
				"grant_type": "client_credentials",
				"client_id": f"{self.client_id}",
				"client_secret": f"{self.client_secret}",
				"audience": "https://api.zscaler.com",
			}

			self.session = requests.Session()
			requests.packages.urllib3.disable_warnings()
			response = self.session.post(uri, headers={}, data=payload, verify=self.ssl_verify)

			if response.status_code == 200:
				returned_session_info = response.json()
				if "expires_in" in returned_session_info:
					expiration_time = int(returned_session_info["expires_in"])
					self.expires_in = time.time() + expiration_time
					if expiration_time == 0:
						self.log.exception(f"[{self.class_name}] Password has expired.")
						raise Exception("Password has expired.")

				if "token_type" in returned_session_info:
					self.token_type = returned_session_info["token_type"]
				else:
					raise Exception("Unexpected authentication result: missing token_type.")

				if "access_token" in returned_session_info:
					self.access_token = returned_session_info["access_token"]
				else:
					raise Exception("Unexpected authentication result: missing access_token.")

				self.headers = {
					"Content-Type": "application/json",
					"Authorization": f"{self.token_type} {self.access_token}",
				}
				self.log.info(f"[{self.class_name}] Authentication successful.")
				return self.session
			else:
				self.log.error(f"[{self.class_name}] Authentication unsuccessful. Response '{response.status_code}'.")
				return None

		except requests.exceptions.RequestException as e:
			raise SystemExit(e) from None

	def get_oneapi_url(self, service):
		base_url = f"https://{self.oneapi_base_fqdn}"
		service = service.lower()
		if service == "zpa":
			return base_url + self.oneapi_zpa_endpoint
		elif service == "zpa_mgmtv1":
			return base_url + self.oneapi_zpa_mgmtv1_endpoint
		elif service == "zpa_mgmtv2":
			return base_url + self.oneapi_zpa_mgmtv2_endpoint
		raise ValueError(f"Unknown service: {service}")

	# ***** HTTP Helper *****

	def action_path(self, service, action, path, addl_headers=None, data=None, allow_http_errors=False):
		if self.session is None:
			self.authenticate()

		act = action.lower()
		# If readonly is enabled, intercept POST, PUT, DELETE write calls.
		if self.readonly and act in ("post", "put", "delete"):
			self.log.info(f"[{self.class_name}] [READONLY MODE] Intercepted and skipped {action.upper()} on {path}")
			# Return a mock response or dictionary representing success/empty state
			if act == "delete":
				class MockResponse:
					status_code = 204
					text = ""
					def json(self): return {}
				return MockResponse()
			# For POST/PUT, we return a dictionary that acts like a mock created entity
			# so that subsequent code gets a valid dictionary with mock details
			mock_id = "mock_id_readonly"
			mock_name = "mock_readonly_entity"
			if isinstance(data, dict):
				mock_id = data.get("id", "mock_id_readonly")
				mock_name = data.get("name", "mock_readonly_entity")
			return {"id": mock_id, "name": mock_name}

		headers = (self.headers | addl_headers) if addl_headers is not None else self.headers

		try:
			url = self.get_oneapi_url(service) + path
			requests.packages.urllib3.disable_warnings()

			if act == "get":
				response = self.session.get(url, headers=headers, verify=self.ssl_verify)
			elif act == "delete":
				response = self.session.delete(url, headers=headers, verify=self.ssl_verify)
			elif act == "post":
				response = self.session.post(url, headers=headers, json=data, verify=self.ssl_verify)
			elif act == "put":
				response = self.session.put(url, headers=headers, json=data, verify=self.ssl_verify)
			else:
				self.log.error(f"[{self.class_name}] Unknown action in object request: {action}")
				return None

			if response.status_code in (200, 201):
				if response.text and response.text.strip():
					return response.json()
				return {}
			elif response.status_code == 204:
				self.log.debug(f"[{self.class_name}] Successful (204 No Content): {action} {path}")
				return response
			elif response.status_code == 401:
				self.log.info(f"[{self.class_name}] Session expired (401); re-authenticating and retrying.")
				self.authenticate()
				return self.action_path(
					service, action, path, addl_headers=addl_headers, data=data, allow_http_errors=allow_http_errors
				)
			elif response.status_code in (409, 412, 429):
				self.log.debug(
					f"[{self.class_name}] Status {response.status_code} (locked/precondition/rate-limit); retrying in 5s."
				)
				time.sleep(5)
				return self.action_path(
					service, action, path, addl_headers=addl_headers, data=data, allow_http_errors=allow_http_errors
				)
			elif response.status_code == 503:
				self.log.error(f"[{self.class_name}] Service is temporarily unavailable.")
				raise SystemExit("Service not available") from None
			else:
				log_fn = self.log.debug if allow_http_errors else self.log.error
				log_fn(f"[{self.class_name}] HTTP {response.status_code} on {action} {path}: {response.text}")
				if data is not None:
					self.log.debug(f"[{self.class_name}] Request payload on {action} {path}: {json.dumps(data)}")
				return response

		except Exception as err:
			self.log.exception(f"[{self.class_name}] Exception on {action} {path}: {err}")
			return None

	# ***** ZPA Customer ID & Microtenants *****

	def get_zpa_customer_id(self):
		if self.oneapi_zpa_customer_id is None:
			session_ids = self.action_path(service="ZPA_MGMTV1", action="GET", path="/admin/me")
			self.log.debug(f"[{self.class_name}] /admin/me -> {session_ids}")
			if isinstance(session_ids, dict):
				self.oneapi_zpa_customer_id = session_ids.get("customerId")
				self.oneapi_zpa_customer_name = session_ids.get("customerName")
				self.oneapi_zpa_microtenant_default_id = session_ids.get("microtenantId")
				self.oneapi_zpa_microtenant_default_name = session_ids.get("microtenantName")

	def get_microtenants(self, microtenant_id=None):
		if self.oneapi_zpa_customer_id is None:
			self.get_zpa_customer_id()

		if microtenant_id is None and self.oneapi_zpa_microtenants is not None:
			return self.oneapi_zpa_microtenants

		if microtenant_id is not None:
			url = f"/admin/customers/{self.oneapi_zpa_customer_id}/microtenants/{microtenant_id}"
			resp = self.action_path("ZPA_MGMTV1", "GET", url)
			return [resp] if isinstance(resp, dict) and "id" in resp else []

		page = 1
		pagesize = 500
		all_mts = []
		while True:
			url = f"/admin/customers/{self.oneapi_zpa_customer_id}/microtenants?page={page}&pagesize={pagesize}"
			response = self.action_path("ZPA_MGMTV1", "GET", url)
			if not isinstance(response, dict):
				break
			if "list" in response:
				all_mts.extend(response["list"])
			total_pages = int(response.get("totalPages", 1))
			if total_pages == 0 or page >= total_pages:
				break
			page += 1

		self.oneapi_zpa_microtenants = all_mts
		return all_mts

	def get_microtenant_id_from_name(self, microtenant_name, microtenant_list=None):
		if microtenant_list is None:
			microtenant_list = self.get_microtenants()
		for microtenant in microtenant_list:
			if microtenant.get("name") == microtenant_name:
				return microtenant.get("id")
		return None

	# ***** Application Segments & Ownership-Aware Sharing *****

	def get_all_application_segments(self, microtenant_id=None):
		if self.oneapi_zpa_customer_id is None:
			self.get_zpa_customer_id()

		page = 1
		pagesize = 500
		final_response = []
		url_base = f"/admin/customers/{self.oneapi_zpa_customer_id}/application?"
		if microtenant_id is not None:
			url_base += f"microtenantId={microtenant_id}&"

		while True:
			url = url_base + f"page={page}&pagesize={pagesize}"
			response = self.action_path("ZPA_MGMTV1", "GET", url, allow_http_errors=True)
			if not isinstance(response, dict):
				break
			if "list" in response:
				final_response.extend(response["list"])
			total_pages = int(response.get("totalPages", 0))
			if total_pages == 0 or page >= total_pages:
				break
			page += 1

		return final_response

	def get_application_segment(self, application_id, microtenant_id=0, allow_http_errors=True):
		url = (
			f"/admin/customers/{self.oneapi_zpa_customer_id}"
			f"/application/{application_id}?microtenantId={microtenant_id}"
		)
		resp = self.action_path("ZPA_MGMTV1", "GET", url, allow_http_errors=allow_http_errors)
		return resp if isinstance(resp, dict) and "id" in resp else None

	def resolve_segment_owner_microtenant_id(self, seg_obj, fallback_mt_id):
		"""
		Determines which Microtenant actually owns an Application Segment:
		- If shared into fallback_mt_id from another Microtenant, uses sharedMicrotenantDetails.sourceMicrotenant.id.
		- Else if seg_obj explicitly carries microtenantId, uses it.
		- Otherwise, because seg_obj came from fallback_mt_id's application list without a sourceMicrotenant,
		  fallback_mt_id IS its owner.
		"""
		if not isinstance(seg_obj, dict) or not seg_obj:
			return None

		details = seg_obj.get("sharedMicrotenantDetails")
		if isinstance(details, dict):
			src_mt = details.get("sourceMicrotenant")
			if isinstance(src_mt, dict) and src_mt.get("id") is not None:
				return str(src_mt["id"])
			if details.get("sourceMicrotenantId") is not None:
				return str(details["sourceMicrotenantId"])

		if "microtenantId" in seg_obj:
			mt_val = seg_obj.get("microtenantId")
			if mt_val is None or str(mt_val).strip() == "":
				return "0"
			return str(mt_val)

		return str(fallback_mt_id) if fallback_mt_id is not None else "0"

	def extract_existing_shared_targets(self, segment):
		targets = set()
		if not isinstance(segment, dict):
			return targets
		for top_key in ("shareToMicrotenants", "sharedToMicrotenants"):
			for item in segment.get(top_key) or []:
				if isinstance(item, dict) and "id" in item:
					targets.add(str(item["id"]))
				elif isinstance(item, (str, int)):
					targets.add(str(item))
		details = segment.get("sharedMicrotenantDetails")
		if isinstance(details, dict):
			for key in ("sharedToMicrotenants", "shareToMicrotenants", "microtenants"):
				for item in details.get(key) or []:
					if isinstance(item, dict) and "id" in item:
						targets.add(str(item["id"]))
					elif isinstance(item, (str, int)):
						targets.add(str(item))
		elif isinstance(details, list):
			for item in details:
				if isinstance(item, dict) and "id" in item:
					targets.add(str(item["id"]))
				elif isinstance(item, (str, int)):
					targets.add(str(item))
		return targets

	def share_application_segment_to_microtenant(
		self, application_id, owner_microtenant_id, target_microtenant_id, existing_shared_targets=None
	):
		targets = set(str(t) for t in (existing_shared_targets or []))
		targets.add(str(target_microtenant_id))
		url = (
			f"/admin/customers/{self.oneapi_zpa_customer_id}"
			f"/application/{application_id}/share?microtenantId={owner_microtenant_id}"
		)
		payload = {"shareToMicrotenants": list(targets)}
		return self.action_path("ZPA_MGMTV1", "PUT", url, data=payload, allow_http_errors=True)

	def ensure_segment_shared_with_target(
		self,
		app_id,
		app_name,
		source_mt_id,
		source_mt_name,
		target_mt_id,
		target_mt_name,
		mt_app_segments_by_id,
		default_app_segments_by_id,
		target_visible_app_ids,
	):
		app_id_str = str(app_id)
		if app_id_str in target_visible_app_ids:
			return True

		seg_obj = mt_app_segments_by_id.get(app_id_str)
		if seg_obj is not None:
			owner_mt_id = self.resolve_segment_owner_microtenant_id(seg_obj, source_mt_id)
		elif app_id_str in default_app_segments_by_id:
			seg_obj = default_app_segments_by_id[app_id_str]
			owner_mt_id = self.resolve_segment_owner_microtenant_id(seg_obj, "0")
		else:
			# Probe source_mt_id first, then Default ('0')
			probed = self.get_application_segment(app_id_str, microtenant_id=source_mt_id, allow_http_errors=True)
			if probed:
				seg_obj = probed
				owner_mt_id = self.resolve_segment_owner_microtenant_id(probed, source_mt_id)
			else:
				probed_def = self.get_application_segment(app_id_str, microtenant_id=0, allow_http_errors=True)
				if probed_def:
					seg_obj = probed_def
					owner_mt_id = self.resolve_segment_owner_microtenant_id(probed_def, "0")
				else:
					self.log.warning(
						f"[{self.class_name}] [Source Microtenant: <{source_mt_name}>] Entity {app_id_str} (<{app_name}>) "
						f"is not a shareable Application Segment; continuing without share call."
					)
					return True

		if str(owner_mt_id) == str(target_mt_id):
			target_visible_app_ids.add(app_id_str)
			return True

		candidate_owners = [str(owner_mt_id)]
		if str(source_mt_id) not in candidate_owners:
			candidate_owners.append(str(source_mt_id))
		if "0" not in candidate_owners:
			candidate_owners.append("0")

		for candidate_owner in candidate_owners:
			owner_seg = self.get_application_segment(
				app_id_str, microtenant_id=candidate_owner, allow_http_errors=True
			)
			if not owner_seg and candidate_owner == str(source_mt_id) and seg_obj:
				owner_seg = seg_obj
			if not owner_seg:
				continue

			# Skip if this candidate_owner is merely a recipient rather than the true owner
			resolved_from_detail = self.resolve_segment_owner_microtenant_id(owner_seg, candidate_owner)
			if resolved_from_detail and resolved_from_detail != candidate_owner and resolved_from_detail in candidate_owners:
				continue

			existing_targets = self.extract_existing_shared_targets(owner_seg)
			if str(target_mt_id) in existing_targets:
				target_visible_app_ids.add(app_id_str)
				return True

			self.log.info(
				f"[{self.class_name}] [Source Microtenant: <{source_mt_name}>] Sharing Application Segment "
				f"<{owner_seg.get('name', app_name)}> ({app_id_str}) from owner Microtenant {candidate_owner} "
				f"to Target <{target_mt_name}> ({target_mt_id})."
			)
			resp = self.share_application_segment_to_microtenant(
				app_id_str, candidate_owner, target_mt_id, existing_shared_targets=existing_targets
			)
			status_code = getattr(resp, "status_code", 200 if isinstance(resp, dict) else None)
			if status_code in (200, 201, 204):
				target_visible_app_ids.add(app_id_str)
				return True

			resp_text = getattr(resp, "text", "") or ""
			if "entity.doesnt.belong.to.microtenant" in resp_text:
				continue

		self.log.error(
			f"[{self.class_name}] [Source Microtenant: <{source_mt_name}>] Failed to share Application Segment "
			f"<{app_name}> ({app_id_str}) with Target <{target_mt_name}>."
		)
		return False

	def is_ip_address_or_subnet(self, possible_ip_data):
		for parser in (
			lambda x: ipaddress.IPv4Address(x),
			lambda x: ipaddress.IPv4Network(x, strict=False),
			lambda x: ipaddress.IPv6Address(x),
			lambda x: ipaddress.IPv6Network(x, strict=False),
		):
			try:
				parser(possible_ip_data)
				return True
			except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
				pass
		return False

	def find_application_segment_ids_using_ip_addresses(self, application_segments, microtenant_label=None):
		ip_segment_ids = set()
		mt_prefix = f"[Source Microtenant: <{microtenant_label}>] " if microtenant_label else ""
		for segment in application_segments:
			domain_names = segment.get("domainNames") or []
			if not domain_names:
				continue
			if any(self.is_ip_address_or_subnet(entry) for entry in domain_names):
				ip_segment_ids.add(str(segment["id"]))
				self.log.info(
					f"[{self.class_name}] {mt_prefix}Application Segment <{segment.get('name')}> uses IP address/subnet "
					f"entries; Policy Groups/Rules referencing it will not be synchronized."
				)
		return ip_segment_ids

	# ***** Dynamic Criteria Discovery & v1 (lhs/rhs) -> v2 (values / entryValues) Converter *****

	def _looks_like_criteria_value(self, key, value):
		if value is None:
			return False
		if key in self.ALL_CRITERIA_KEYS:
			return True
		k_low = str(key).lower()
		if "criteria" in k_low or "condition" in k_low:
			return isinstance(value, (list, dict, str))
		if isinstance(value, dict) and any(
			subk in value for subk in ("operands", "conditions", "criteria", "subCriteria", "expressions")
		):
			return True
		if isinstance(value, list) and len(value) > 0 and isinstance(value[0], dict) and any(
			subk in value[0] for subk in ("operands", "objectType", "criteriaType", "operandType")
		):
			return True
		return False

	def discover_object_criteria_keys(self, obj, base_keys):
		"""
		Returns all criteria keys present on obj (combining known base_keys + any dynamically
		detected criteria/condition keys on the Policy Group or Rule).
		"""
		keys = list(base_keys)
		if isinstance(obj, dict):
			for k, v in obj.items():
				if k in self.EMBEDDED_RULE_COLLECTION_KEYS or k in self.NON_APP_METADATA_KEYS:
					continue
				if k not in keys and self._looks_like_criteria_value(k, v):
					keys.append(k)
		return tuple(keys)

	def _uses_values_format(self, obj_type, operand):
		obj_type_up = str(obj_type or "").upper()
		if obj_type_up in self.VALUES_OBJECT_TYPES or obj_type_up in self.APP_OBJECT_TYPES:
			return True
		if obj_type_up in self.ENTRY_VALUES_OBJECT_TYPES:
			return False

		if isinstance(operand.get("entryValues"), list) and len(operand["entryValues"]) > 0:
			return False
		if isinstance(operand.get("values"), list) and len(operand["values"]) > 0:
			return True
		if isinstance(operand.get("rhsValues"), list) and len(operand["rhsValues"]) > 0:
			first = operand["rhsValues"][0]
			return not (isinstance(first, dict) and "lhs" in first and "rhs" in first)

		lhs_val = operand.get("lhs")
		if lhs_val is None or str(lhs_val).strip().lower() in ("", "id", "none", obj_type_up.lower()):
			return True
		return False

	def _resolve_operand_object_type(self, operand):
		for t_key in ("objectType", "criteriaType", "operandType", "field"):
			val = operand.get(t_key)
			if val is not None and str(val).strip() != "":
				return str(val).strip()
		lhs_val = str(operand.get("lhs") or "").strip()
		if lhs_val.upper() in (self.VALUES_OBJECT_TYPES | self.ENTRY_VALUES_OBJECT_TYPES | self.APP_OBJECT_TYPES):
			return lhs_val.upper()
		t_val = str(operand.get("type") or "").strip()
		if t_val.upper() in (self.VALUES_OBJECT_TYPES | self.ENTRY_VALUES_OBJECT_TYPES | self.APP_OBJECT_TYPES):
			return t_val.upper()
		return ""

	def _extract_operand_items(self, operand):
		obj_type = self._resolve_operand_object_type(operand)
		if not obj_type:
			return None, None, []

		if self._uses_values_format(obj_type, operand):
			vals = []
			for list_key in ("values", "rhsValues", "ids", "appSegmentIds", "applicationIds", "appIds"):
				raw_list = operand.get(list_key)
				if isinstance(raw_list, list) and len(raw_list) > 0:
					for v in raw_list:
						cand = (v.get("id") if v.get("id") is not None else v.get("rhs")) if isinstance(v, dict) else v
						if cand is not None and str(cand).strip() != "":
							vals.append(str(cand).strip())
					break
				elif isinstance(raw_list, (str, int)) and str(raw_list).strip() != "":
					vals.extend(p.strip() for p in str(raw_list).split(",") if p.strip())
					break

			if not vals:
				for single_key in ("rhs", "rhsValue", "value"):
					sv = operand.get(single_key)
					if sv is not None and str(sv).strip() != "":
						vals.append(str(sv).strip())
						break

			if not vals and isinstance(operand.get("entryValues"), list):
				for ev in operand["entryValues"]:
					if isinstance(ev, dict) and ev.get("rhs") is not None:
						vals.append(str(ev["rhs"]).strip())

			# Normalize APP aliases to canonical ZPA v2 'APP'
			if obj_type.upper() in self.APP_OBJECT_TYPES:
				obj_type = "APP"

			dedup_vals = list(dict.fromkeys(vals))
			return obj_type, "values", dedup_vals
		else:
			entries = []
			if isinstance(operand.get("entryValues"), list) and len(operand["entryValues"]) > 0:
				for ev in operand["entryValues"]:
					if isinstance(ev, dict) and ev.get("lhs") is not None and ev.get("rhs") is not None:
						entries.append({"lhs": str(ev["lhs"]), "rhs": str(ev["rhs"])})
			elif isinstance(operand.get("rhsValues"), list) and len(operand["rhsValues"]) > 0:
				for ev in operand["rhsValues"]:
					if isinstance(ev, dict) and ev.get("lhs") is not None and ev.get("rhs") is not None:
						entries.append({"lhs": str(ev["lhs"]), "rhs": str(ev["rhs"])})
					elif operand.get("lhs") is not None and ev is not None:
						entries.append({"lhs": str(operand["lhs"]), "rhs": str(ev)})
			else:
				rhs_val = operand.get("rhs") if operand.get("rhs") is not None else operand.get("rhsValue")
				if rhs_val is None:
					rhs_val = operand.get("value")
				if operand.get("lhs") is not None and rhs_val is not None:
					entries.append({"lhs": str(operand["lhs"]), "rhs": str(rhs_val)})

			dedup_entries = []
			seen_pairs = set()
			for item in entries:
				pair = (item["lhs"], item["rhs"])
				if pair not in seen_pairs:
					seen_pairs.add(pair)
					dedup_entries.append(item)
			return obj_type, "entryValues", dedup_entries

	def _convert_condition_block(self, cond_block):
		if not isinstance(cond_block, dict):
			return []

		block_op = str(cond_block.get("operator") or "OR").upper()
		block_negated = cond_block.get("negated")

		out_base = {"operator": block_op}
		if block_negated is not None:
			out_base["negated"] = bool(block_negated)

		nested_fields = {}
		for nested_key in ("conditions", "subCriteria", "criteria", "expressions"):
			if isinstance(cond_block.get(nested_key), list) and len(cond_block[nested_key]) > 0:
				converted_nested = []
				for sub in cond_block[nested_key]:
					converted_nested.extend(self._convert_condition_block(sub))
				if converted_nested:
					nested_fields[nested_key] = converted_nested

		raw_operands = cond_block.get("operands")
		if not isinstance(raw_operands, list) or len(raw_operands) == 0:
			# Support single-operand condition dict without an outer 'operands' list
			if self._resolve_operand_object_type(cond_block):
				raw_operands = [cond_block]
			elif nested_fields:
				merged_block = copy.deepcopy(out_base)
				merged_block.update(nested_fields)
				return [merged_block]
			else:
				return []

		if block_op == "OR":
			grouped = {}
			group_order = []
			passthrough_operands = []

			for op in raw_operands:
				if not isinstance(op, dict):
					continue
				if not self._resolve_operand_object_type(op):
					passthrough_operands.extend(self._convert_condition_block(op))
					continue

				obj_type, mode, items = self._extract_operand_items(op)
				if not obj_type or not items:
					continue
				op_neg = bool(op["negated"]) if "negated" in op and op["negated"] is not None else None
				g_key = (obj_type, mode, op_neg)
				if g_key not in grouped:
					grouped[g_key] = []
					group_order.append(g_key)
				grouped[g_key].extend(items)

			final_operands = []
			for obj_type, mode, op_neg in group_order:
				items = grouped[(obj_type, mode, op_neg)]
				if mode == "values":
					op_payload = {"objectType": obj_type, "values": list(dict.fromkeys(items))}
				else:
					dedup = []
					seen = set()
					for ev in items:
						pair = (ev["lhs"], ev["rhs"])
						if pair not in seen:
							seen.add(pair)
							dedup.append(ev)
					op_payload = {"objectType": obj_type, "entryValues": dedup}
				if op_neg is not None:
					op_payload["negated"] = op_neg
				final_operands.append(op_payload)

			final_operands.extend(passthrough_operands)
			if not final_operands and not nested_fields:
				return []

			result_block = copy.deepcopy(out_base)
			if final_operands:
				result_block["operands"] = final_operands
			result_block.update(nested_fields)
			return [result_block]

		else:
			buckets = []
			for op in raw_operands:
				if not isinstance(op, dict):
					continue
				obj_type, mode, items = self._extract_operand_items(op)
				if not obj_type or not items:
					continue
				op_payload = {"objectType": obj_type, mode: items}
				if "negated" in op and op["negated"] is not None:
					op_payload["negated"] = bool(op["negated"])

				placed = False
				for bucket in buckets:
					if obj_type not in bucket:
						bucket[obj_type] = op_payload
						placed = True
						break
				if not placed:
					buckets.append({obj_type: op_payload})

			result_blocks = []
			for idx, bucket in enumerate(buckets):
				b_obj = copy.deepcopy(out_base)
				b_obj["operands"] = list(bucket.values())
				if idx == 0 and nested_fields:
					b_obj.update(nested_fields)
				result_blocks.append(b_obj)

			if not result_blocks and nested_fields:
				b_obj = copy.deepcopy(out_base)
				b_obj.update(nested_fields)
				result_blocks.append(b_obj)

			return result_blocks

	def _transform_criteria_for_write(self, node):
		if node is None:
			return None

		if isinstance(node, str):
			s_strip = node.strip()
			if s_strip.startswith("{") or s_strip.startswith("["):
				try:
					parsed = json.loads(s_strip)
					return self._transform_criteria_for_write(parsed)
				except Exception:
					return node
			return node

		if isinstance(node, list):
			converted_list = []
			for item in node:
				converted_list.extend(self._convert_condition_block(item))
			return converted_list

		if not isinstance(node, dict):
			return node

		if ("operands" in node or self._resolve_operand_object_type(node)) and not any(
			k in node for k in ("groupCriteria", "commonCriteria", "policyCriteria")
		):
			converted = self._convert_condition_block(node)
			return converted[0] if len(converted) == 1 else {"operator": "AND", "conditions": converted}

		cleaned = {}
		for k, v in node.items():
			if k in (
				"id",
				"creationTime",
				"modifiedTime",
				"modifiedBy",
				"policySetId",
				"policyGroupSetId",
				"policyGroupSetGid",
				"policyGroupId",
				"policyGroupGid",
				"groupSetId",
				"groupId",
				"ruleId",
				"microtenantId",
				"microtenantName",
			):
				continue
			if v is None:
				continue

			if k == "operator":
				cleaned["operator"] = "AND"
			elif k in ("conditions", "criteria", "subCriteria", "expressions") and isinstance(v, list):
				conv = []
				for item in v:
					conv.extend(self._convert_condition_block(item))
				cleaned[k] = conv
			elif isinstance(v, (dict, list)):
				cleaned[k] = self._transform_criteria_for_write(v)
			else:
				cleaned[k] = copy.deepcopy(v)

		return cleaned

	# ***** Tier 1: Policy Group Sets *****

	def get_policy_group_set(self, policy_type="ACCESS_POLICY", microtenant_id=None, create_if_not_exist=True):
		if self.oneapi_zpa_customer_id is None:
			self.get_zpa_customer_id()

		url = (
			f"/admin/customers/{self.oneapi_zpa_customer_id}"
			f"/policyGroupSet/policyType/{policy_type}?createIfNotExist={str(create_if_not_exist).lower()}"
		)
		if microtenant_id is not None:
			url += f"&microtenantId={microtenant_id}"

		response = self.action_path("ZPA_MGMTV1", "GET", url)
		return response if isinstance(response, dict) else None

	def get_policy_set_id(self, policy_type="ACCESS_POLICY", microtenant_id=None):
		url = f"/admin/customers/{self.oneapi_zpa_customer_id}/policySet/policyType/{policy_type}"
		if microtenant_id is not None:
			url += f"?microtenantId={microtenant_id}"
		resp = self.action_path("ZPA_MGMTV1", "GET", url, allow_http_errors=True)
		if isinstance(resp, dict) and "id" in resp:
			return str(resp["id"])
		return None

	# ***** Tier 2: Policy Groups & groupCriteria / commonCriteria *****

	def _unwrap_entity(self, response, wrapper_keys):
		if isinstance(response, list) and len(response) == 1 and isinstance(response[0], dict):
			response = response[0]
		if not isinstance(response, dict):
			return None
		if ("params" in response and "reason" in response) or (
			isinstance(response.get("id"), str) and "." in response.get("id", "") and "name" not in response
		):
			return None
		if "id" in response:
			return response
		for key in wrapper_keys:
			inner = response.get(key)
			if isinstance(inner, dict) and "id" in inner:
				return inner
		# Fallback: check any nested dict value carrying both 'id' and 'name'
		for inner in response.values():
			if isinstance(inner, dict) and "id" in inner and "name" in inner:
				return inner
		return None

	def _unwrap_collection(self, response, candidate_keys):
		if isinstance(response, list):
			return response
		if isinstance(response, dict):
			for key in candidate_keys:
				val = response.get(key)
				if isinstance(val, list):
					return val
				if isinstance(val, dict):
					for subkey in candidate_keys:
						if isinstance(val.get(subkey), list):
							return val[subkey]
		return []

	def _merge_non_null(self, base_dict, override_dict):
		"""
		Merges summary and detailed group/rule dicts without letting None overwrite a populated field.
		"""
		merged = copy.deepcopy(base_dict) if isinstance(base_dict, dict) else {}
		if isinstance(override_dict, dict):
			for k, v in override_dict.items():
				if v is None and k in merged and merged[k] is not None:
					continue
				merged[k] = v
		return merged

	def get_policy_group(self, group_set_id, group_id, microtenant_id=None):
		url = (
			f"/admin/customers/{self.oneapi_zpa_customer_id}"
			f"/policyGroupSet/{group_set_id}/group/{group_id}"
		)
		if microtenant_id is not None:
			url += f"?microtenantId={microtenant_id}"
		response = self.action_path("ZPA_MGMTV1", "GET", url)
		return self._unwrap_entity(response, ("group", "policyGroup", "policyGroupDto", "data", "result"))

	def get_all_policy_groups(self, group_set_or_id, microtenant_id=None, hydrate_details=True):
		if isinstance(group_set_or_id, dict):
			group_set = group_set_or_id
			group_set_id = str(group_set["id"])
		else:
			group_set = {}
			group_set_id = str(group_set_or_id)

		url = (
			f"/admin/customers/{self.oneapi_zpa_customer_id}"
			f"/policyGroupSet/{group_set_id}/group/all"
		)
		if microtenant_id is not None:
			url += f"?microtenantId={microtenant_id}"

		response = self.action_path("ZPA_MGMTV1", "GET", url)
		summary_groups = self._unwrap_collection(
			response, ("list", "groups", "policyGroups", "data", "items", "content")
		)

		ordered_ids = []
		summary_by_id = {}
		for grp in summary_groups:
			if isinstance(grp, dict) and grp.get("id"):
				gid = str(grp["id"])
				if gid not in summary_by_id:
					ordered_ids.append(gid)
					summary_by_id[gid] = grp

		for gid in group_set.get("customPolicyGroupGids") or []:
			gid_str = str(gid)
			if gid_str and gid_str not in summary_by_id:
				ordered_ids.append(gid_str)
				summary_by_id[gid_str] = {"id": gid_str}

		default_gid = group_set.get("defaultPolicyGroupGid")
		if default_gid:
			default_gid_str = str(default_gid)
			if default_gid_str not in summary_by_id:
				ordered_ids.append(default_gid_str)
				summary_by_id[default_gid_str] = {"id": default_gid_str}

		if not hydrate_details:
			return [summary_by_id[gid] for gid in ordered_ids if "id" in summary_by_id[gid]]

		detailed_groups = []
		for gid in ordered_ids:
			full_grp = self.get_policy_group(group_set_id, gid, microtenant_id=microtenant_id)
			if full_grp:
				merged = self._merge_non_null(summary_by_id.get(gid, {}), full_grp)
				detailed_groups.append(merged)
			elif "name" in summary_by_id[gid]:
				detailed_groups.append(summary_by_id[gid])

		return detailed_groups

	def is_default_policy_group(self, group_obj, default_group_gid=None):
		gid = str(group_obj.get("id", ""))
		if default_group_gid and gid == str(default_group_gid):
			return True
		if any(bool(group_obj.get(flag)) for flag in ("defaultGroup", "isDefault", "defaultPolicyGroup")):
			return True
		for type_key in ("type", "groupType", "policyGroupType"):
			val = str(group_obj.get(type_key, "")).upper()
			if "DEFAULT" in val:
				return True
		return False

	def is_global_policy_group(self, group_obj, global_group_gid=None):
		gid = str(group_obj.get("id", ""))
		if global_group_gid and gid == str(global_group_gid):
			return True
		if any(bool(group_obj.get(flag)) for flag in ("globalGroup", "isGlobal", "globalPolicyGroup")):
			return True
		for type_key in ("type", "groupType", "policyGroupType"):
			val = str(group_obj.get(type_key, "")).upper()
			if "GLOBAL" in val:
				return True
		return False

	def discover_custom_group_type_fields(self, groups, default_gid=None, global_gid=None):
		template = {}
		for grp in groups or []:
			if not isinstance(grp, dict):
				continue
			if self.is_default_policy_group(grp, default_gid) or self.is_global_policy_group(grp, global_gid):
				continue
			for key in ("type", "groupType", "policyGroupType"):
				if key in grp and grp[key] is not None:
					template[key] = grp[key]
			if template:
				break
		return template

	def has_non_empty_criteria(self, obj, criteria_keys=None):
		if not isinstance(obj, dict):
			return False
		effective_keys = self.discover_object_criteria_keys(obj, criteria_keys or self.ALL_CRITERIA_KEYS)
		for key in effective_keys:
			if self._canonicalize_criteria(obj.get(key)) is not None:
				return True
		return False

	def clean_policy_group_payload(
		self,
		policy_group,
		target_group_name,
		target_group_set_id,
		custom_type_template=None,
		existing_target_group=None,
	):
		cleaned = copy.deepcopy(policy_group)

		keys_to_remove = [
			"id",
			"creationTime",
			"modifiedTime",
			"modifiedBy",
			"groupOrder",
			"ruleOrder",
			"order",
			"permissionLevel",
			"restrictedEntity",
			"rules",
			"policyRules",
			"accessRules",
			"ruleGids",
			"customRuleGids",
			"ruleCount",
			"totalRules",
			"criteriaCount",
			"microtenantId",
			"microtenantName",
			"appConnectorGroups",
			"appServerGroups",
			"defaultGroup",
			"globalGroup",
			"isDefault",
			"isGlobal",
			"defaultPolicyGroup",
			"globalPolicyGroup",
			"systemGroup",
			"predefined",
			"readOnly",
		]
		for key in keys_to_remove:
			cleaned.pop(key, None)

		cleaned["name"] = target_group_name

		if "operator" in cleaned and cleaned["operator"]:
			cleaned["operator"] = "AND"

		for gs_key in ("policyGroupSetGid", "policyGroupSetId", "groupSetId"):
			if gs_key in cleaned or (existing_target_group and gs_key in existing_target_group):
				cleaned[gs_key] = str(target_group_set_id)

		custom_type_template = custom_type_template or {}
		for type_key in ("type", "groupType", "policyGroupType"):
			if existing_target_group and type_key in existing_target_group and existing_target_group[type_key]:
				cleaned[type_key] = existing_target_group[type_key]
			elif type_key in custom_type_template:
				cleaned[type_key] = custom_type_template[type_key]
			elif type_key in cleaned and isinstance(cleaned[type_key], str):
				val = cleaned[type_key]
				if "DEFAULT" in val.upper():
					cleaned[type_key] = (
						val.replace("DEFAULT", "CUSTOM").replace("Default", "Custom").replace("default", "custom")
					)

		effective_group_crit_keys = self.discover_object_criteria_keys(cleaned, self.GROUP_CRITERIA_KEYS)
		if existing_target_group:
			effective_group_crit_keys = self.discover_object_criteria_keys(
				existing_target_group, effective_group_crit_keys
			)

		has_any_populated_criteria = False
		for crit_key in effective_group_crit_keys:
			if crit_key in cleaned and cleaned[crit_key] is not None:
				transformed = self._transform_criteria_for_write(cleaned[crit_key])
				cleaned[crit_key] = transformed
				if self._canonicalize_criteria(transformed) is not None:
					has_any_populated_criteria = True

		if has_any_populated_criteria:
			for crit_key in effective_group_crit_keys:
				if crit_key in cleaned and self._canonicalize_criteria(cleaned[crit_key]) is None:
					cleaned.pop(crit_key, None)
		elif existing_target_group:
			for crit_key in effective_group_crit_keys:
				if (
					crit_key in existing_target_group
					and self._canonicalize_criteria(existing_target_group[crit_key]) is not None
				):
					cleaned[crit_key] = [] if isinstance(existing_target_group[crit_key], list) else {}

		return cleaned

	def _minimal_policy_group_payload(self, full_payload):
		dynamic_crit_keys = self.discover_object_criteria_keys(full_payload, self.GROUP_CRITERIA_KEYS)
		allowed = (
			"id",
			"name",
			"description",
			"disabled",
			"enabled",
			"action",
			"operator",
			"type",
			"groupType",
			"policyGroupType",
			"policyGroupSetGid",
			*dynamic_crit_keys,
			*self.DIRECT_APP_CONTAINER_KEYS,
		)
		seen = set()
		result = {}
		for k in allowed:
			if k not in seen and k in full_payload and full_payload[k] is not None:
				seen.add(k)
				result[k] = copy.deepcopy(full_payload[k])
		return result

	def add_policy_group(
		self,
		group_set_id,
		policy_group,
		target_group_name,
		microtenant_id=None,
		custom_type_template=None,
	):
		payload = self.clean_policy_group_payload(
			policy_group,
			target_group_name,
			group_set_id,
			custom_type_template=custom_type_template,
		)
		url = (
			f"/admin/customers/{self.oneapi_zpa_customer_id}"
			f"/policyGroupSet/{group_set_id}/group"
		)
		if microtenant_id is not None:
			url += f"?microtenantId={microtenant_id}"

		response = self.action_path("ZPA_MGMTV1", "POST", url, data=payload, allow_http_errors=True)
		created = self._unwrap_entity(response, ("group", "policyGroup", "policyGroupDto", "data", "result"))

		if not created:
			min_payload = self._minimal_policy_group_payload(payload)
			min_payload_no_type = {
				k: v
				for k, v in min_payload.items()
				if k not in ("type", "groupType", "policyGroupType", "policyGroupSetGid")
			}
			self.log.info(
				f"[{self.class_name}] Retrying Policy Group POST for '{target_group_name}' with minimal v2 payload."
			)
			response = self.action_path("ZPA_MGMTV1", "POST", url, data=min_payload_no_type)
			created = self._unwrap_entity(response, ("group", "policyGroup", "policyGroupDto", "data", "result"))

		if not created:
			return None

		new_group_id = str(created["id"])

		if self.has_non_empty_criteria(policy_group, self.GROUP_CRITERIA_KEYS):
			hydrated = self.get_policy_group(group_set_id, new_group_id, microtenant_id=microtenant_id) or created
			if self.compare_criteria(policy_group, hydrated, self.GROUP_CRITERIA_KEYS) != 2:
				self.log.info(
					f"[{self.class_name}] Applying groupCriteria via PUT to newly created Policy Group '{target_group_name}'."
				)
				self.update_policy_group(
					group_set_id,
					new_group_id,
					policy_group,
					target_group_name,
					microtenant_id=microtenant_id,
					custom_type_template=custom_type_template,
					existing_target_group=hydrated,
				)

		return self.get_policy_group(group_set_id, new_group_id, microtenant_id=microtenant_id) or created

	def update_policy_group(
		self,
		group_set_id,
		group_id,
		policy_group,
		target_group_name,
		microtenant_id=None,
		custom_type_template=None,
		existing_target_group=None,
	):
		payload = self.clean_policy_group_payload(
			policy_group,
			target_group_name,
			group_set_id,
			custom_type_template=custom_type_template,
			existing_target_group=existing_target_group,
		)
		payload["id"] = str(group_id)
		url = (
			f"/admin/customers/{self.oneapi_zpa_customer_id}"
			f"/policyGroupSet/{group_set_id}/group/{group_id}"
		)
		if microtenant_id is not None:
			url += f"?microtenantId={microtenant_id}"

		response = self.action_path("ZPA_MGMTV1", "PUT", url, data=payload, allow_http_errors=True)
		status_code = getattr(
			response,
			"status_code",
			200 if self._unwrap_entity(response, ("group", "policyGroup", "policyGroupDto", "data", "result")) else None,
		)
		if status_code not in (200, 201, 204):
			min_payload = self._minimal_policy_group_payload(payload)
			self.log.info(
				f"[{self.class_name}] Retrying Policy Group PUT for '{target_group_name}' with minimal v2 payload."
			)
			response = self.action_path("ZPA_MGMTV1", "PUT", url, data=min_payload)

		return response

	def reorder_policy_group(self, group_set_id, group_id, new_order, microtenant_id=None):
		url = (
			f"/admin/customers/{self.oneapi_zpa_customer_id}"
			f"/policyGroupSet/{group_set_id}/group/{group_id}/reorder/{new_order}"
		)
		if microtenant_id is not None:
			url += f"?microtenantId={microtenant_id}"
		return self.action_path("ZPA_MGMTV1", "PUT", url, allow_http_errors=True)

	def delete_policy_group(self, group_set_id, group_id, microtenant_id=None):
		url = (
			f"/admin/customers/{self.oneapi_zpa_customer_id}"
			f"/policyGroupSet/{group_set_id}/group/{group_id}"
		)
		if microtenant_id is not None:
			url += f"?microtenantId={microtenant_id}"
		return self.action_path("ZPA_MGMTV1", "DELETE", url)

	# ***** Tier 3: Policy Group Rules & policyCriteria *****

	def get_policy_group_rule(self, group_set_id, group_id, rule_id, microtenant_id=None):
		url = (
			f"/admin/customers/{self.oneapi_zpa_customer_id}"
			f"/policyGroupSet/{group_set_id}/group/{group_id}/rule/{rule_id}"
		)
		if microtenant_id is not None:
			url += f"?microtenantId={microtenant_id}"
		response = self.action_path("ZPA_MGMTV1", "GET", url, allow_http_errors=True)
		return self._unwrap_entity(response, ("rule", "policyRule", "policyRuleDto", "data", "result"))

	def get_policy_group_rules(
		self, group_set_id, group_id, microtenant_id=None, group_obj=None, hydrate_details=True
	):
		base_path = (
			f"/admin/customers/{self.oneapi_zpa_customer_id}"
			f"/policyGroupSet/{group_set_id}/group/{group_id}/rule"
		)
		raw_rules = []
		endpoint_succeeded = False

		for size_param in ("pageSize=100", "pagesize=100", None):
			page = 1
			attempt_rules = []
			while True:
				q_parts = []
				if microtenant_id is not None:
					q_parts.append(f"microtenantId={microtenant_id}")
				if size_param:
					q_parts.append(f"page={page}&{size_param}")
				query = ("?" + "&".join(q_parts)) if q_parts else ""

				response = self.action_path("ZPA_MGMTV1", "GET", base_path + query, allow_http_errors=True)
				if isinstance(response, list):
					attempt_rules.extend(response)
					endpoint_succeeded = True
					break
				elif isinstance(response, dict) and "params" not in response:
					items = self._unwrap_collection(
						response, ("list", "rules", "policyRules", "accessRules", "data", "items", "content")
					)
					attempt_rules.extend(items)
					endpoint_succeeded = True
					total_pages = int(response.get("totalPages", 0))
					if not size_param or total_pages == 0 or page >= total_pages:
						break
					page += 1
				else:
					break

			if endpoint_succeeded:
				raw_rules = attempt_rules
				break

		if not raw_rules and isinstance(group_obj, dict):
			for key in ("rules", "policyRules", "accessRules"):
				if isinstance(group_obj.get(key), list) and group_obj[key]:
					raw_rules.extend(group_obj[key])
					break
			if not raw_rules:
				for gid_key in ("ruleGids", "customRuleGids"):
					if isinstance(group_obj.get(gid_key), list) and group_obj[gid_key]:
						raw_rules.extend({"id": str(rid)} for rid in group_obj[gid_key])
						break

		detailed_rules = []
		seen_ids = set()
		for item in raw_rules:
			if isinstance(item, (str, int)):
				rid = str(item)
				summary_item = {"id": rid}
			elif isinstance(item, dict) and item.get("id"):
				rid = str(item["id"])
				summary_item = item
			else:
				continue

			if rid in seen_ids:
				continue
			seen_ids.add(rid)

			if not hydrate_details and "name" in summary_item and (
				"ruleOrder" in summary_item or "order" in summary_item
			):
				detailed_rules.append(summary_item)
				continue

			full_rule = self.get_policy_group_rule(group_set_id, group_id, rid, microtenant_id=microtenant_id)
			if full_rule:
				detailed_rules.append(self._merge_non_null(summary_item, full_rule))
			elif "name" in summary_item:
				detailed_rules.append(summary_item)

		return detailed_rules

	def clean_rule_payload(
		self,
		rule,
		target_rule_name,
		target_group_set_id,
		target_group_id,
		target_policy_set_id=None,
		source_group_set_id=None,
		source_group_id=None,
	):
		cleaned = copy.deepcopy(rule)
		src_policy_set_id = str(cleaned.get("policySetId", ""))

		keys_to_remove = [
			"id",
			"creationTime",
			"modifiedTime",
			"modifiedBy",
			"ruleOrder",
			"order",
			"permissionLevel",
			"restrictedEntity",
			"microtenantId",
			"microtenantName",
			"appConnectorGroups",
			"appServerGroups",
			"defaultRule",
			"defaultRuleName",
		]
		for key in keys_to_remove:
			cleaned.pop(key, None)

		cleaned["name"] = target_rule_name

		if "operator" in cleaned and cleaned["operator"]:
			cleaned["operator"] = "AND"

		for gs_key in ("policyGroupSetGid", "policyGroupSetId", "groupSetId"):
			if gs_key in cleaned:
				cleaned[gs_key] = str(target_group_set_id)
		for g_key in ("policyGroupGid", "policyGroupId", "groupId"):
			if g_key in cleaned:
				cleaned[g_key] = str(target_group_id)

		if "policySetId" in cleaned:
			if source_group_id and src_policy_set_id == str(source_group_id):
				cleaned["policySetId"] = str(target_group_id)
			elif source_group_set_id and src_policy_set_id == str(source_group_set_id):
				cleaned["policySetId"] = str(target_group_set_id)
			elif target_policy_set_id:
				cleaned["policySetId"] = str(target_policy_set_id)
			else:
				cleaned.pop("policySetId", None)

		effective_rule_crit_keys = self.discover_object_criteria_keys(cleaned, self.ALL_CRITERIA_KEYS)
		has_any_populated_criteria = False
		for crit_key in effective_rule_crit_keys:
			if crit_key in cleaned and cleaned[crit_key] is not None:
				transformed = self._transform_criteria_for_write(cleaned[crit_key])
				cleaned[crit_key] = transformed
				if self._canonicalize_criteria(transformed) is not None:
					has_any_populated_criteria = True

		if has_any_populated_criteria:
			for crit_key in effective_rule_crit_keys:
				if crit_key in cleaned and self._canonicalize_criteria(cleaned[crit_key]) is None:
					cleaned.pop(crit_key, None)

		return cleaned

	def _minimal_rule_payload(self, full_payload):
		dynamic_crit_keys = self.discover_object_criteria_keys(full_payload, self.RULE_CRITERIA_KEYS)
		allowed = (
			"id",
			"name",
			"description",
			"action",
			"actionId",
			"customMsg",
			"bypassDefaultRule",
			"operator",
			"negated",
			"disabled",
			"enabled",
			"policyType",
			*dynamic_crit_keys,
		)
		seen = set()
		result = {}
		for k in allowed:
			if k not in seen and k in full_payload and full_payload[k] is not None:
				seen.add(k)
				result[k] = copy.deepcopy(full_payload[k])
		return result

	def _inject_group_app_values_if_needed(self, payload, inherited_group_app_ids):
		if not inherited_group_app_ids:
			return None
		patched = copy.deepcopy(payload)
		app_block = {
			"operator": "OR",
			"operands": [{"objectType": "APP", "values": sorted(str(a) for a in inherited_group_app_ids)}],
		}
		injected = False
		for crit_key in ("policyCriteria", "ruleCriteria", "conditions", "criteria"):
			if crit_key in patched:
				val = patched[crit_key]
				if isinstance(val, list):
					val.insert(0, app_block)
					injected = True
					break
				elif isinstance(val, dict):
					conds = val.setdefault("conditions", [])
					if isinstance(conds, list):
						conds.insert(0, app_block)
						injected = True
						break
		if not injected:
			patched["conditions"] = [app_block]
		return patched

	def add_policy_group_rule(
		self,
		group_set_id,
		group_id,
		rule,
		target_rule_name,
		microtenant_id=None,
		target_policy_set_id=None,
		source_group_set_id=None,
		source_group_id=None,
		inherited_group_app_ids=None,
	):
		payload = self.clean_rule_payload(
			rule,
			target_rule_name,
			group_set_id,
			group_id,
			target_policy_set_id=target_policy_set_id,
			source_group_set_id=source_group_set_id,
			source_group_id=source_group_id,
		)
		url = (
			f"/admin/customers/{self.oneapi_zpa_customer_id}"
			f"/policyGroupSet/{group_set_id}/group/{group_id}/rule"
		)
		if microtenant_id is not None:
			url += f"?microtenantId={microtenant_id}"

		response = self.action_path("ZPA_MGMTV1", "POST", url, data=payload, allow_http_errors=True)
		created = self._unwrap_entity(response, ("rule", "policyRule", "policyRuleDto", "data", "result"))

		if not created:
			min_payload = self._minimal_rule_payload(payload)
			resp_text = getattr(response, "text", "") or ""
			if (
				"APP" in resp_text
				and inherited_group_app_ids
				and not self.get_application_segments_in_object(rule, is_group=False)
			):
				min_payload = (
					self._inject_group_app_values_if_needed(min_payload, inherited_group_app_ids) or min_payload
				)
			self.log.info(
				f"[{self.class_name}] Retrying Rule POST for '{target_rule_name}' with minimal v2 payload."
			)
			response = self.action_path("ZPA_MGMTV1", "POST", url, data=min_payload)
			created = self._unwrap_entity(response, ("rule", "policyRule", "policyRuleDto", "data", "result"))

		return created

	def update_policy_group_rule(
		self,
		group_set_id,
		group_id,
		rule_id,
		rule,
		target_rule_name,
		microtenant_id=None,
		target_policy_set_id=None,
		source_group_set_id=None,
		source_group_id=None,
		inherited_group_app_ids=None,
	):
		payload = self.clean_rule_payload(
			rule,
			target_rule_name,
			group_set_id,
			group_id,
			target_policy_set_id=target_policy_set_id,
			source_group_set_id=source_group_set_id,
			source_group_id=source_group_id,
		)
		payload["id"] = str(rule_id)
		mt_query = f"?microtenantId={microtenant_id}" if microtenant_id is not None else ""

		group_rule_url = (
			f"/admin/customers/{self.oneapi_zpa_customer_id}"
			f"/policyGroupSet/{group_set_id}/group/{group_id}/rule/{rule_id}{mt_query}"
		)
		resp = self.action_path("ZPA_MGMTV1", "PUT", group_rule_url, data=payload, allow_http_errors=True)
		status_code = getattr(
			resp,
			"status_code",
			200 if self._unwrap_entity(resp, ("rule", "policyRule", "policyRuleDto", "data", "result")) else None,
		)

		if status_code in (200, 201, 204):
			return resp

		self.log.info(
			f"[{self.class_name}] In-place PUT returned {status_code} for Rule '{target_rule_name}'; "
			f"recreating rule in Policy Group {group_id}."
		)
		self.delete_policy_group_rule(group_set_id, group_id, rule_id, microtenant_id=microtenant_id)
		return self.add_policy_group_rule(
			group_set_id,
			group_id,
			rule,
			target_rule_name,
			microtenant_id=microtenant_id,
			target_policy_set_id=target_policy_set_id,
			source_group_set_id=source_group_set_id,
			source_group_id=source_group_id,
			inherited_group_app_ids=inherited_group_app_ids,
		)

	def reorder_policy_group_rule(self, group_set_id, group_id, rule_id, new_order, microtenant_id=None):
		url = (
			f"/admin/customers/{self.oneapi_zpa_customer_id}"
			f"/policyGroupSet/{group_set_id}/group/{group_id}/rule/{rule_id}/reorder/{new_order}"
		)
		if microtenant_id is not None:
			url += f"?microtenantId={microtenant_id}"
		return self.action_path("ZPA_MGMTV1", "PUT", url, allow_http_errors=True)

	def delete_policy_group_rule(self, group_set_id, group_id, rule_id, microtenant_id=None):
		url = (
			f"/admin/customers/{self.oneapi_zpa_customer_id}"
			f"/policyGroupSet/{group_set_id}/group/{group_id}/rule/{rule_id}"
		)
		if microtenant_id is not None:
			url += f"?microtenantId={microtenant_id}"
		return self.action_path("ZPA_MGMTV1", "DELETE", url)

	# ***** Comprehensive Application Segment Extraction & Canonical Diffing *****

	def get_application_segments_in_object(self, policy_obj, known_app_segments_by_id=None, is_group=False):
		"""
		Extracts all Application Segment IDs -> Names from a Policy Group (when is_group=True)
		or a Policy Group Rule (when is_group=False):
		- Walks the ENTIRE object (excluding embedded rule lists when inspecting a Policy Group,
		  so group-level vs rule-level Application Segments remain cleanly separated).
		- Detects APP operands across any criteria key (groupCriteria, commonCriteria,
		  policyGroupCriteria, policyCriteria, conditions, applications, appSegments, etc.)
		  and any operand schema (values, value, rhs, rhsValue, rhsValues, entryValues, JSON strings).
		- Also matches any nested value against known_app_segments_by_id so no ZPA Policy Group
		  criteria representation can ever hide a referenced Application Segment.
		"""
		app_segments = {}
		known_app_segments_by_id = known_app_segments_by_id or {}

		def _record_id(candidate_id, fallback_name=None):
			if candidate_id is None:
				return
			cid = str(candidate_id).strip()
			if not cid or cid.lower() in ("id", "app", "application", "true", "false", "and", "or", "none"):
				return
			# Support comma-delimited ID strings if present
			if "," in cid:
				for part in cid.split(","):
					_record_id(part, fallback_name)
				return
			if cid in known_app_segments_by_id:
				app_segments[cid] = known_app_segments_by_id[cid].get("name", cid)
			elif fallback_name is not None:
				app_segments[cid] = fallback_name
			else:
				app_segments[cid] = cid

		def _is_app_operand_dict(d):
			for t_key in ("objectType", "criteriaType", "operandType", "field", "lhs", "type"):
				val = d.get(t_key)
				if val is not None and str(val).strip().upper() in self.APP_OBJECT_TYPES:
					return True
			return False

		def _walk(node, in_app_context=False, is_root=False):
			if node is None:
				return

			if isinstance(node, list):
				for item in node:
					_walk(item, in_app_context=in_app_context, is_root=False)
				return

			if isinstance(node, (str, int)):
				if isinstance(node, bool):
					return
				s_val = str(node).strip()
				if not s_val:
					return
				if s_val.startswith("{") or s_val.startswith("["):
					try:
						parsed = json.loads(s_val)
						_walk(parsed, in_app_context=in_app_context, is_root=False)
						return
					except Exception:
						pass
				if in_app_context or s_val in known_app_segments_by_id:
					_record_id(s_val)
				return

			if not isinstance(node, dict):
				return

			is_app_node = in_app_context or _is_app_operand_dict(node)

			if is_app_node and not is_root:
				name_hint = node.get("name")
				for single_key in ("rhs", "rhsValue", "value", "appId", "applicationId", "appSegmentId"):
					if node.get(single_key) is not None and not isinstance(node.get(single_key), (dict, list)):
						_record_id(node[single_key], name_hint)
				for list_key in (
					"values",
					"rhsValues",
					"ids",
					"appSegmentIds",
					"applicationIds",
					"appIds",
					"gids",
				):
					raw_l = node.get(list_key)
					if isinstance(raw_l, list):
						for val in raw_l:
							if isinstance(val, dict):
								_record_id(val.get("id") or val.get("rhs"), val.get("name") or name_hint)
							else:
								_record_id(val, name_hint)
					elif isinstance(raw_l, (str, int)):
						_record_id(raw_l, name_hint)
				for ev in node.get("entryValues") or []:
					if isinstance(ev, dict):
						_record_id(ev.get("rhs") or ev.get("id"), ev.get("name") or name_hint)
				# Direct application object e.g. {'id': '72068...', 'name': 'MyApp'} inside applications list
				if "id" in node and (
					in_app_context
					or str(node["id"]) in known_app_segments_by_id
					or not any(k in node for k in ("operands", "conditions", "lhs", "rhs"))
				):
					if not (in_app_context is False and "operands" in node):
						_record_id(node["id"], name_hint)

			for key, value in node.items():
				if is_root and key == "id":
					continue
				if is_group and key in self.EMBEDDED_RULE_COLLECTION_KEYS:
					continue
				if key in self.NON_APP_METADATA_KEYS:
					continue
				if key in ("operator", "negated", "objectType", "criteriaType", "operandType"):
					continue
				if key == "lhs" and not (isinstance(value, (str, int)) and str(value) in known_app_segments_by_id):
					continue

				key_is_app = key in self.DIRECT_APP_CONTAINER_KEYS
				if isinstance(value, (dict, list)):
					_walk(value, in_app_context=(in_app_context or key_is_app), is_root=False)
				elif isinstance(value, (str, int)) and not isinstance(value, bool):
					s_val = str(value).strip()
					if s_val.startswith("{") or s_val.startswith("["):
						try:
							parsed = json.loads(s_val)
							_walk(parsed, in_app_context=(in_app_context or key_is_app), is_root=False)
							continue
						except Exception:
							pass
					if key_is_app or (not is_root and key != "id" and s_val in known_app_segments_by_id):
						_record_id(s_val, node.get("name"))

		if isinstance(policy_obj, dict):
			_walk(policy_obj, in_app_context=False, is_root=True)

		return app_segments

	def _canonicalize_v2_tree(self, node):
		if node is None:
			return None

		if isinstance(node, list):
			items = [self._canonicalize_v2_tree(item) for item in node]
			items = [item for item in items if item is not None]
			if not items:
				return None
			return tuple(sorted(items, key=lambda x: json.dumps(x, sort_keys=True, default=str)))

		if isinstance(node, dict):
			canon = {}
			for k, v in node.items():
				if k == "negated" and v is False:
					continue
				cv = self._canonicalize_v2_tree(v)
				if cv is None:
					continue
				canon[k] = cv

			meaningful = set(canon.keys()) - {"operator", "negated"}
			if not meaningful:
				return None
			return canon

		if isinstance(node, bool):
			return node
		s = str(node).strip()
		return s if s != "" else None

	def _canonicalize_criteria(self, node):
		if node is None:
			return None
		v2_node = self._transform_criteria_for_write(node)
		return self._canonicalize_v2_tree(v2_node)

	def _combined_canonical_criteria(self, obj, criteria_keys):
		if not isinstance(obj, dict):
			return None
		effective_keys = self.discover_object_criteria_keys(obj, criteria_keys)
		combined = []
		for key in effective_keys:
			c = self._canonicalize_criteria(obj.get(key))
			if c is not None:
				combined.append(c)
		if not combined:
			return None
		return combined[0] if len(combined) == 1 else tuple(combined)

	def compare_criteria(self, source_obj, target_obj, criteria_keys=None):
		base_keys = criteria_keys or self.ALL_CRITERIA_KEYS
		src_c = self._combined_canonical_criteria(source_obj, base_keys)
		tgt_c = self._combined_canonical_criteria(target_obj, base_keys)
		return 2 if src_c == tgt_c else 1

	def compare_policy_group(self, source_group, target_group, expected_target_name):
		if target_group.get("name") != expected_target_name:
			return 0

		for field in ("description", "disabled", "action"):
			if field in source_group or field in target_group:
				if str(source_group.get(field, "")) != str(target_group.get(field, "")):
					return 1

		return self.compare_criteria(source_group, target_group, self.GROUP_CRITERIA_KEYS)

	def compare_policy_rule(self, source_rule, target_rule, expected_rule_name):
		if target_rule.get("name") != expected_rule_name:
			return 0

		for field in ("action", "description", "customMsg", "disabled"):
			if field in source_rule or field in target_rule:
				if str(source_rule.get(field, "")) != str(target_rule.get(field, "")):
					return 1

		return self.compare_criteria(source_rule, target_rule, self.RULE_CRITERIA_KEYS)


# ***** Logging *****

LOG_MSG_FORMAT = "[%(asctime)s] %(levelname)s <pid:%(process)d> %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H-%M-%S"
LOG_LEVELS_TXT = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
LOG_LEVELS_ENUM = [log.DEBUG, log.INFO, log.WARNING, log.ERROR, log.CRITICAL]


def log_namer(log_path):
	base_path_with_base_name = log_path.split(".")[0]
	return base_path_with_base_name + "." + str(date.today()) + ".log"


def init_logs(log_base_name, log_level_txt, logs_dir=None):
	try:
		valid_path = False
		if logs_dir is not None:
			if not os.path.exists(logs_dir):
				os.makedirs(logs_dir)
			valid_path = os.access(logs_dir, os.W_OK)
	except Exception as e:
		raise Exception(f"Unexpected error while initializing logs: {e}")

	if not valid_path:
		logs_dir = os.path.dirname(os.path.realpath(__file__))
		if not os.access(logs_dir, os.W_OK):
			raise Exception(f"Error: Unable to write to backup log directory '{logs_dir}'")

	try:
		log_name = log_namer(log_base_name)
		log_path = os.path.join(logs_dir, log_name)
		log_level = LOG_LEVELS_ENUM[LOG_LEVELS_TXT.index(log_level_txt)]

		root_log = log.getLogger()
		formatter = log.Formatter(fmt=LOG_MSG_FORMAT, datefmt=LOG_DATE_FORMAT)
		handler = logging.handlers.TimedRotatingFileHandler(log_path, when="midnight", interval=1, backupCount=7)
		handler.namer = log_namer
		handler.setFormatter(formatter)
		handler.setLevel(log_level)
		root_log.addHandler(handler)
		root_log.setLevel(log_level)
	except Exception as e:
		raise Exception(f"Unexpected error while configuring log format: {e}")

	return log_path


# ***** Configuration Loader *****

class YAMLLoader(yaml.SafeLoader):
	def __init__(self, stream: IO) -> None:
		try:
			self._root = os.path.split(stream.name)[0]
		except AttributeError:
			self._root = os.path.curdir
		super().__init__(stream)


def construct_include(loader: YAMLLoader, node: yaml.Node) -> Any:
	filename = os.path.abspath(os.path.join(loader._root, loader.construct_scalar(node)))
	extension = os.path.splitext(filename).lstrip(".")
	with open(filename, "r") as f:
		if extension in ("yaml", "yml"):
			return yaml.load(f, YAMLLoader)


yaml.add_constructor("!include", construct_include, YAMLLoader)


def yamlread(fn):
	try:
		if fn is not None:
			with open(fn) as fh:
				return yaml.load(fh, YAMLLoader)
	except FileNotFoundError:
		return None
	return None


def get_parameters_from_config(filename, keys):
	config_file = yamlread(filename)
	if config_file is None:
		print(f"[PolicyGroupSync] Configuration file '{filename}' not found or empty.")
		return None

	error = False
	for tenant_key in keys:
		if tenant_key not in config_file:
			# Optional keys such as readonly should not trigger an error
			if tenant_key == "readonly":
				continue
			print(f"[PolicyGroupSync] Key '{tenant_key}' missing in configuration file '{filename}'.")
			error = True

	return None if error else config_file


def get_parameters():
	parser = argparse.ArgumentParser(description="Synchronize ZPA Policy Groups, groupCriteria, and Rules")
	parser.add_argument("--config", required=False)
	parser.add_argument("--ssl_verify", default=False, required=False)
	parser.add_argument("--log_level", default="DEBUG", required=False)
	parser.add_argument("--readonly", action="store_true", default=False, help="Readonly / dry-run mode")
	args = parser.parse_args()

	parameters = {
		"ssl_verify": args.ssl_verify,
		"log_level": args.log_level,
		"readonly": args.readonly,
	}

	keys = ["vanity_domain", "client_id", "client_secret", "target", "skiplist", "readonly"]
	if args.config:
		config_file_parameters = get_parameters_from_config(args.config, keys) or {}
		for key in keys:
			if key in config_file_parameters:
				parameters[key] = config_file_parameters[key]

	if "readonly" not in parameters:
		parameters["readonly"] = False

	if isinstance(parameters["readonly"], str):
		parameters["readonly"] = parameters["readonly"].lower() in ("true", "1", "yes")

	return parameters


# ***** Summary Table Formatting Helpers *****

def new_microtenant_stats():
	return {
		"groups_created": 0,
		"groups_updated": 0,
		"groups_unchanged": 0,
		"groups_filtered": 0,
		"groups_deleted": 0,
		"rules_created": 0,
		"rules_updated": 0,
		"rules_unchanged": 0,
		"rules_filtered": 0,
		"rules_deleted": 0,
	}


def _render_ascii_table(headers, rows, footer_row=None):
	all_rows = [headers] + list(rows) + ([footer_row] if footer_row else [])
	col_widths = [
		max(len(str(r[col_idx])) for r in all_rows) for col_idx in range(len(headers))
	]

	sep = "+" + "+".join("-" * (w + 2) for w in col_widths) + "+"

	def _fmt_row(row):
		return "|" + "|".join(f" {str(val).ljust(col_widths[i])} " for i, val in enumerate(row)) + "|"

	lines = [sep, _fmt_row(headers), sep]
	if rows:
		for r in rows:
			lines.append(_fmt_row(r))
	else:
		empty_msg = "No active Source Microtenants processed"
		inner_width = len(sep) - 4
		lines.append(f"| {empty_msg.ljust(inner_width)} |")

	lines.append(sep)
	if footer_row:
		lines.append(_fmt_row(footer_row))
		lines.append(sep)
	return lines


def log_final_summary_tables(
	target_microtenant,
	preserved_local_group_count,
	mt_order,
	mt_stats_by_name,
	synced_group_details,
	base_group_order,
):
	"""
	Logs a final INFO-level summary table per Source Microtenant and an ordered breakdown
	of synced Custom Policy Groups in the Target Microtenant.
	"""
	log.info(
		f"[Policy Group Sync] Step 7: Logging final synchronization summary for Target Microtenant "
		f"<{target_microtenant}> ({preserved_local_group_count} local custom group(s) preserved, "
		f"C=Created, U=Updated, ==Unchanged):"
	)

	mt_headers = [
		"Source Microtenant",
		"Groups Synced (C/U/=)",
		"Groups Filtered",
		"Groups Deleted",
		"Rules Synced (C/U/=)",
		"Rules Filtered",
		"Rules Deleted",
	]

	mt_rows = []
	totals = new_microtenant_stats()

	for mt_name in mt_order:
		st = mt_stats_by_name[mt_name]
		for k in totals:
			totals[k] += st[k]

		g_synced = st["groups_created"] + st["groups_updated"] + st["groups_unchanged"]
		r_synced = st["rules_created"] + st["rules_updated"] + st["rules_unchanged"]

		mt_rows.append(
			[
				mt_name,
				f"{g_synced} ({st['groups_created']}/{st['groups_updated']}/{st['groups_unchanged']})",
				str(st["groups_filtered"]),
				str(st["groups_deleted"]),
				f"{r_synced} ({st['rules_created']}/{st['rules_updated']}/{st['rules_unchanged']})",
				str(st["rules_filtered"]),
				str(st["rules_deleted"]),
			]
		)

	tot_g_synced = totals["groups_created"] + totals["groups_updated"] + totals["groups_unchanged"]
	tot_r_synced = totals["rules_created"] + totals["rules_updated"] + totals["rules_unchanged"]
	mt_footer = [
		"TOTAL",
		f"{tot_g_synced} ({totals['groups_created']}/{totals['groups_updated']}/{totals['groups_unchanged']})",
		str(totals["groups_filtered"]),
		str(totals["groups_deleted"]),
		f"{tot_r_synced} ({totals['rules_created']}/{totals['rules_updated']}/{totals['rules_unchanged']})",
		str(totals["rules_filtered"]),
		str(totals["rules_deleted"]),
	]

	for line in _render_ascii_table(mt_headers, mt_rows, footer_row=mt_footer):
		log.info(f"[Policy Group Sync] {line}")

	if synced_group_details:
		log.info(
			f"[Policy Group Sync] Synced Custom Policy Groups in Target <{target_microtenant}> (in evaluation order):"
		)
		grp_headers = [
			"Order",
			"Source Microtenant",
			"Target Policy Group",
			"Group Status",
			"Rules Synced (C/U/=)",
			"Rules Deleted",
		]
		grp_rows = []
		for offset, gd in enumerate(synced_group_details):
			rs = gd["rule_stats"]
			r_tot = rs["rules_created"] + rs["rules_updated"] + rs["rules_unchanged"]
			grp_rows.append(
				[
					str(base_group_order + offset),
					gd["source_mt_name"],
					gd["target_group_name"],
					gd["group_action"],
					f"{r_tot} ({rs['rules_created']}/{rs['rules_updated']}/{rs['rules_unchanged']})",
					str(rs["rules_deleted"]),
				]
			)
		for line in _render_ascii_table(grp_headers, grp_rows):
			log.info(f"[Policy Group Sync] {line}")


# ***** Policy Group & Rule Synchronization *****

def format_prefixed_name(mt_name, raw_name):
	prefix = f"{mt_name} - "
	if raw_name.startswith(prefix):
		return raw_name
	return f"{prefix}{raw_name}"


def _extract_numeric_rule_order(rule_obj):
	raw = rule_obj.get("ruleOrder") if rule_obj.get("ruleOrder") is not None else rule_obj.get("order")
	if raw is not None and str(raw).strip().isdigit():
		return int(str(raw).strip())
	return None


def align_rules_order_within_group(
	tenant,
	target_group_set_id,
	target_group_id,
	target_group_name,
	desired_rule_names_in_order,
	microtenant_name,
	target_mt_id,
):
	"""
	Aligns rule evaluation order inside a Policy Group using ZPA's continuous PolicyGroupSet
	ruleOrder window [group_start_order .. group_start_order + N - 1].
	"""
	rule_count = len(desired_rule_names_in_order)
	if rule_count <= 1:
		log.info(
			f"[Policy Group Sync] [Source Microtenant: <{microtenant_name}>] Policy Group '{target_group_name}' "
			f"has {rule_count} active Rule(s); no rule reordering required."
		)
		return

	live_rules = tenant.get_policy_group_rules(
		target_group_set_id,
		target_group_id,
		microtenant_id=target_mt_id,
		hydrate_details=False,
	)
	if len(live_rules) <= 1:
		return

	numeric_orders = [_extract_numeric_rule_order(r) for r in live_rules]
	valid_orders = [o for o in numeric_orders if o is not None]
	if not valid_orders:
		return

	live_sorted = sorted(
		live_rules,
		key=lambda r: (_extract_numeric_rule_order(r) if _extract_numeric_rule_order(r) is not None else 10**9),
	)
	current_names_in_order = [r.get("name", "") for r in live_sorted]

	if current_names_in_order == desired_rule_names_in_order:
		log.info(
			f"[Policy Group Sync] [Source Microtenant: <{microtenant_name}>] All {rule_count} Rules in "
			f"'{target_group_name}' are already in exact evaluation order "
			f"(ruleOrder {min(valid_orders)}..{max(valid_orders)})."
		)
		return

	group_start_order = min(valid_orders)
	live_by_name = {r.get("name"): r for r in live_rules if r.get("name") and r.get("id")}

	log.info(
		f"[Policy Group Sync] [Source Microtenant: <{microtenant_name}>] Aligning evaluation order for "
		f"{rule_count} Rules in '{target_group_name}' within PolicyGroupSet window "
		f"[{group_start_order}..{group_start_order + rule_count - 1}]..."
	)

	for offset, expected_name in enumerate(desired_rule_names_in_order):
		r_obj = live_by_name.get(expected_name)
		if not r_obj:
			continue
		desired_global_order = group_start_order + offset
		curr_order = _extract_numeric_rule_order(r_obj)
		if curr_order == desired_global_order:
			continue

		log.info(
			f"[Policy Group Sync] [Source Microtenant: <{microtenant_name}>]   = Reordering Rule '{expected_name}' "
			f"in '{target_group_name}' to ruleOrder {desired_global_order}."
		)
		resp = tenant.reorder_policy_group_rule(
			target_group_set_id,
			target_group_id,
			r_obj["id"],
			desired_global_order,
			microtenant_id=target_mt_id,
		)
		if hasattr(resp, "status_code") and resp.status_code == 400:
			try:
				err_json = resp.json()
				if err_json.get("id") == "invalid.rule.neworder.start" and len(err_json.get("params", [])) >= 2:
					group_start_order = int(err_json["params"])
					adjusted_order = group_start_order + offset
					tenant.reorder_policy_group_rule(
						target_group_set_id,
						target_group_id,
						r_obj["id"],
						adjusted_order,
						microtenant_id=target_mt_id,
					)
			except Exception:
				pass


def sync_rules_within_group(
	tenant,
	target_group_set_id,
	target_group_id,
	target_group_name,
	valid_source_rules,
	microtenant_name,
	target_mt_id,
	target_policy_set_id=None,
	source_group_set_id=None,
	source_group_id=None,
	inherited_group_app_ids=None,
	target_group_obj=None,
):
	"""
	Synchronizes all associated Rules and their policyCriteria inside the target Policy Group,
	logging every execution stage with the active source Microtenant name and returning rule counts.
	"""
	log.info(
		f"[Policy Group Sync] [Source Microtenant: <{microtenant_name}>] Retrieving existing Rules from "
		f"Target Policy Group '{target_group_name}' ({target_group_id})..."
	)
	existing_target_rules = tenant.get_policy_group_rules(
		target_group_set_id,
		target_group_id,
		microtenant_id=target_mt_id,
		group_obj=target_group_obj,
	)
	rules_to_delete = list(existing_target_rules)
	rule_plan = {}
	desired_rule_names_in_order = []

	log.info(
		f"[Policy Group Sync] [Source Microtenant: <{microtenant_name}>] Comparing {len(valid_source_rules)} "
		f"valid source Rule(s) against {len(existing_target_rules)} existing target Rule(s) in '{target_group_name}'..."
	)
	for idx, src_rule in enumerate(valid_source_rules, start=1):
		expected_rule_name = format_prefixed_name(microtenant_name, src_rule["name"])
		desired_rule_names_in_order.append(expected_rule_name)
		matched = False

		for tgt_rule in existing_target_rules:
			cmp_res = tenant.compare_policy_rule(src_rule, tgt_rule, expected_rule_name)
			if cmp_res == 2:
				matched = True
				if tgt_rule in rules_to_delete:
					rules_to_delete.remove(tgt_rule)
				rule_plan[idx] = {"status": "no_change", "target_rule": tgt_rule, "name": expected_rule_name}
				break
			elif cmp_res == 1:
				matched = True
				if tgt_rule in rules_to_delete:
					rules_to_delete.remove(tgt_rule)
				rule_plan[idx] = {
					"status": "update",
					"source_rule": src_rule,
					"rule_id": tgt_rule["id"],
					"name": expected_rule_name,
				}
				break

		if not matched:
			rule_plan[idx] = {"status": "new", "source_rule": src_rule, "name": expected_rule_name}

	planned_create = sum(1 for v in rule_plan.values() if v["status"] == "new")
	planned_update = sum(1 for v in rule_plan.values() if v["status"] == "update")
	planned_unchanged = sum(1 for v in rule_plan.values() if v["status"] == "no_change")
	log.info(
		f"[Policy Group Sync] [Source Microtenant: <{microtenant_name}>] Rules plan for '{target_group_name}': "
		f"{planned_create} to create, {planned_update} to update, {planned_unchanged} unchanged, "
		f"{len(rules_to_delete)} to delete."
	)

	log.info(
		f"[Policy Group Sync] [Source Microtenant: <{microtenant_name}>] Applying Rule creates/updates "
		f"in Target Policy Group '{target_group_name}'..."
	)
	actual_created = 0
	actual_updated = 0
	actual_unchanged = 0

	for idx, action_item in rule_plan.items():
		status = action_item["status"]
		r_name = action_item["name"]
		if status == "new":
			log.info(
				f"[Policy Group Sync] [Source Microtenant: <{microtenant_name}>]   + Creating Rule '{r_name}' "
				f"in '{target_group_name}'."
			)
			res = tenant.add_policy_group_rule(
				target_group_set_id,
				target_group_id,
				action_item["source_rule"],
				r_name,
				microtenant_id=target_mt_id,
				target_policy_set_id=target_policy_set_id,
				source_group_set_id=source_group_set_id,
				source_group_id=source_group_id,
				inherited_group_app_ids=inherited_group_app_ids,
			)
			if res:
				actual_created += 1
		elif status == "update":
			log.info(
				f"[Policy Group Sync] [Source Microtenant: <{microtenant_name}>]   ~ Updating Rule '{r_name}' "
				f"in '{target_group_name}'."
			)
			res = tenant.update_policy_group_rule(
				target_group_set_id,
				target_group_id,
				action_item["rule_id"],
				action_item["source_rule"],
				r_name,
				microtenant_id=target_mt_id,
				target_policy_set_id=target_policy_set_id,
				source_group_set_id=source_group_set_id,
				source_group_id=source_group_id,
				inherited_group_app_ids=inherited_group_app_ids,
			)
			if res is not None:
				actual_updated += 1
		elif status == "no_change":
			actual_unchanged += 1

	log.info(
		f"[Policy Group Sync] [Source Microtenant: <{microtenant_name}>] Checking stale Rules to remove from "
		f"Target Policy Group '{target_group_name}' ({len(rules_to_delete)} to remove)..."
	)
	actual_deleted = 0
	for stale_rule in rules_to_delete:
		if "id" in stale_rule:
			log.info(
				f"[Policy Group Sync] [Source Microtenant: <{microtenant_name}>]   - Deleting stale Rule "
				f"'{stale_rule.get('name')}' from '{target_group_name}'."
			)
			tenant.delete_policy_group_rule(
				target_group_set_id, target_group_id, stale_rule["id"], microtenant_id=target_mt_id
			)
			actual_deleted += 1

	align_rules_order_within_group(
		tenant=tenant,
		target_group_set_id=target_group_set_id,
		target_group_id=target_group_id,
		target_group_name=target_group_name,
		desired_rule_names_in_order=desired_rule_names_in_order,
		microtenant_name=microtenant_name,
		target_mt_id=target_mt_id,
	)

	return {
		"rules_created": actual_created,
		"rules_updated": actual_updated,
		"rules_unchanged": actual_unchanged,
		"rules_deleted": actual_deleted,
	}


def sync():
	parameters = get_parameters()
	init_logs("PolicyGroupSync", parameters["log_level"])

	# Step 1: Authenticate to ZPA via OneAPI
	log.info("[Policy Group Sync] Step 1: Authenticating to ZPA tenant via OneAPI...")
	tenant = OneAPI(
		vanity_domain=parameters["vanity_domain"],
		client_id=parameters["client_id"],
		client_secret=parameters["client_secret"],
		log=log,
		ssl_verify=parameters["ssl_verify"],
		readonly=parameters.get("readonly", False),
	)
	if parameters.get("readonly", False):
		log.info("[Policy Group Sync] Running in READ-ONLY/DRY-RUN mode. No changes will be made to the target Microtenant.")

	tenant.authenticate()

	# Step 2: Discover Microtenants & resolve Target / Skiplist
	log.info("[Policy Group Sync] Step 2: Discovering Microtenants and resolving Target and Skiplist configurations...")
	microtenants = tenant.get_microtenants()
	target_microtenant = parameters["target"]
	target_microtenant_id = tenant.get_microtenant_id_from_name(target_microtenant, microtenants)
	if target_microtenant_id is None:
		log.error(f"[Policy Group Sync] Target microtenant '{target_microtenant}' not found. Exiting...")
		return

	skip_microtenant_ids = set()
	for tenant_to_skip in parameters.get("skiplist") or []:
		skip_id = tenant.get_microtenant_id_from_name(tenant_to_skip, microtenants)
		if skip_id is not None:
			skip_microtenant_ids.add(skip_id)
		else:
			log.error(f"[Policy Group Sync] Skiplist microtenant '{tenant_to_skip}' not found. Exiting...")
			return

	log.info(
		f"[Policy Group Sync] Discovered {len(microtenants)} total Microtenant(s); "
		f"Target is <{target_microtenant}> ({target_microtenant_id}), skipping {len(skip_microtenant_ids)} configured skiplist Microtenant(s)."
	)

	# Step 3: Retrieve Target Microtenant Policy Group Set, Default/Target Application Segments, & hydrated Policy Groups
	log.info(
		f"[Policy Group Sync] Step 3: Retrieving existing Policy Group Set, Application Segments, & Policy Groups "
		f"for Target Microtenant <{target_microtenant}>..."
	)
	target_group_set = tenant.get_policy_group_set("ACCESS_POLICY", microtenant_id=target_microtenant_id)
	if not target_group_set or "id" not in target_group_set:
		log.error(
			f"[Policy Group Sync] Could not retrieve ACCESS_POLICY Policy Group Set for target '{target_microtenant}'."
		)
		return

	target_group_set_id = str(target_group_set["id"])
	target_policy_set_id = tenant.get_policy_set_id("ACCESS_POLICY", microtenant_id=target_microtenant_id)
	target_default_gid = str(target_group_set.get("defaultPolicyGroupGid", ""))
	target_global_gid = str(target_group_set.get("globalPolicyGroupGid", ""))
	target_protected_gids = {gid for gid in (target_default_gid, target_global_gid) if gid}

	log.info(
		f"[Policy Group Sync] Preloading Application Segments in Default and Target Microtenant <{target_microtenant}>..."
	)
	default_app_segments = tenant.get_all_application_segments(microtenant_id=0)
	default_app_segments_by_id = {str(seg["id"]): seg for seg in default_app_segments if "id" in seg}
	default_ip_segment_ids = tenant.find_application_segment_ids_using_ip_addresses(default_app_segments)

	target_app_segments = tenant.get_all_application_segments(microtenant_id=target_microtenant_id)
	target_app_segments_by_id = {str(seg["id"]): seg for seg in target_app_segments if "id" in seg}
	target_visible_app_ids = set(target_app_segments_by_id.keys())
	target_ip_segment_ids = tenant.find_application_segment_ids_using_ip_addresses(target_app_segments)

	log.info(
		f"[Policy Group Sync] Hydrating and classifying existing Policy Groups in Target Microtenant <{target_microtenant}>..."
	)
	existing_target_groups = tenant.get_all_policy_groups(target_group_set, microtenant_id=target_microtenant_id)
	custom_type_template = tenant.discover_custom_group_type_fields(
		existing_target_groups, default_gid=target_default_gid, global_gid=target_global_gid
	)

	all_other_mt_prefixes = tuple(
		f"{mt['name']} - "
		for mt in microtenants
		if mt.get("name") and mt.get("id") != target_microtenant_id
	)

	local_target_custom_groups = []
	synced_target_groups_pool = []
	has_global_group = bool(target_global_gid)

	for t_grp in existing_target_groups:
		t_gid = str(t_grp.get("id", ""))
		t_name = t_grp.get("name", "")
		if tenant.is_global_policy_group(t_grp, target_global_gid):
			has_global_group = True
			continue
		if t_gid in target_protected_gids or tenant.is_default_policy_group(t_grp, target_default_gid):
			continue
		### jkraenzle
		# What if Microtenant name changes? Do we wnat to keep groups that only start with target microtenant and not all other Microtenant names?
		if t_name.startswith(target_microtenant) or not t_name.startswith(all_other_mt_prefixes):
			local_target_custom_groups.append(t_grp)
		else:
			synced_target_groups_pool.append(t_grp)

	log.info(
		f"[Policy Group Sync] Target Microtenant <{target_microtenant}> summary: "
		f"{len(existing_target_groups)} total group(s), {len(local_target_custom_groups)} local custom group(s) preserved, "
		f"{len(synced_target_groups_pool)} existing synced group(s) in pool."
	)

	first_custom_order = 2 if has_global_group else 1
	desired_synced_groups_in_order = []
	matched_target_group_ids = set()

	# Summary tracking structures
	mt_order = []
	mt_stats_by_name = {}
	synced_group_details = []

	def _get_mt_stats(name):
		if name not in mt_stats_by_name:
			mt_stats_by_name[name] = new_microtenant_stats()
			mt_order.append(name)
		return mt_stats_by_name[name]

	# Step 4: Iterate through Source Microtenants: Sync Policy Groups + groupCriteria + Rules (policyCriteria)
	log.info("[Policy Group Sync] Step 4: Beginning synchronization loop across Source Microtenants...")
	for microtenant in microtenants:
		mt_id = microtenant.get("id")
		mt_name = microtenant.get("name", "<unknown>")
		if not mt_id or not microtenant.get("name"):
			continue

		# Step 4.1: Check whether Source Microtenant is Target or in Skiplist
		if mt_id == target_microtenant_id or mt_id in skip_microtenant_ids:
			log.info(
				f"[Policy Group Sync] [Source Microtenant: <{mt_name}>] Step 4.1: Skipping Microtenant "
				f"({'Target Microtenant' if mt_id == target_microtenant_id else 'in Skiplist'})."
			)
			continue

		mt_stats = _get_mt_stats(mt_name)
		log.info(
			f"[Policy Group Sync] [Source Microtenant: <{mt_name}>] Step 4.1: Starting synchronization for active Source Microtenant <{mt_name}> ({mt_id})..."
		)

		# Step 4.2: Retrieve Source Microtenant Policy Group Set & hydrated Policy Groups
		log.info(
			f"[Policy Group Sync] [Source Microtenant: <{mt_name}>] Step 4.2: Retrieving ACCESS_POLICY Policy Group Set and hydrating Policy Groups..."
		)
		source_group_set = tenant.get_policy_group_set("ACCESS_POLICY", microtenant_id=mt_id)
		if not source_group_set or "id" not in source_group_set:
			log.warning(
				f"[Policy Group Sync] [Source Microtenant: <{mt_name}>] No ACCESS_POLICY Policy Group Set found; skipping Microtenant."
			)
			continue

		source_group_set_id = str(source_group_set["id"])
		source_default_gid = str(source_group_set.get("defaultPolicyGroupGid", ""))
		source_global_gid = str(source_group_set.get("globalPolicyGroupGid", ""))

		source_groups = tenant.get_all_policy_groups(source_group_set, microtenant_id=mt_id)
		if not custom_type_template:
			custom_type_template = tenant.discover_custom_group_type_fields(
				source_groups, default_gid=source_default_gid, global_gid=source_global_gid
			)

		# Step 4.3: Retrieve Source Microtenant Application Segments & identify IP-based segments
		log.info(
			f"[Policy Group Sync] [Source Microtenant: <{mt_name}>] Step 4.3: Retrieving Application Segments and checking for IP-based segments..."
		)
		mt_app_segments = tenant.get_all_application_segments(microtenant_id=mt_id)
		mt_app_segments_by_id = {str(seg["id"]): seg for seg in mt_app_segments if "id" in seg}
		known_app_segments_by_id = {
			**default_app_segments_by_id,
			**target_app_segments_by_id,
			**mt_app_segments_by_id,
		}
		ip_segment_ids = (
			tenant.find_application_segment_ids_using_ip_addresses(mt_app_segments, microtenant_label=mt_name)
			| default_ip_segment_ids
			| target_ip_segment_ids
		)

		# Step 4.4: Iterate through Policy Groups in Source Microtenant
		log.info(
			f"[Policy Group Sync] [Source Microtenant: <{mt_name}>] Step 4.4: Processing {len(source_groups)} Policy Group(s)..."
		)

		for src_group in source_groups:
			src_gid = str(src_group.get("id", ""))
			src_gname = src_group.get("name", "")
			if not src_gid or not src_gname:
				continue

			if tenant.is_global_policy_group(src_group, source_global_gid):
				log.info(
					f"[Policy Group Sync] [Source Microtenant: <{mt_name}>] Skipping Global Policy Group '{src_gname}'."
				)
				continue

			is_default_grp = tenant.is_default_policy_group(src_group, source_default_gid)
			target_group_name = (
				f"{mt_name} - Default Group" if is_default_grp else format_prefixed_name(mt_name, src_gname)
			)
			log.info(
				f"[Policy Group Sync] [Source Microtenant: <{mt_name}>] Evaluating {'Default' if is_default_grp else 'Custom'} "
				f"Policy Group '{src_gname}' -> Target Custom Policy Group '{target_group_name}'..."
			)
			log.debug(
				f"[Policy Group Sync] [Source Microtenant: <{mt_name}>] Policy Group '{src_gname}' keys: {list(src_group.keys())}"
			)

			# Inspect Policy Group criteria / fields for Application Segments & IP restrictions
			log.info(
				f"[Policy Group Sync] [Source Microtenant: <{mt_name}>] Inspecting Policy Group '{src_gname}' "
				f"criteria for Application Segments and IP restrictions..."
			)
			group_app_segments = tenant.get_application_segments_in_object(
				src_group, known_app_segments_by_id, is_group=True
			)
			if group_app_segments:
				log.info(
					f"[Policy Group Sync] [Source Microtenant: <{mt_name}>] Policy Group '{src_gname}' defines "
					f"{len(group_app_segments)} Application Segment(s) at Group level: {list(group_app_segments.values())}."
				)

			if any(app_id in ip_segment_ids for app_id in group_app_segments):
				log.warning(
					f"[Policy Group Sync] [Source Microtenant: <{mt_name}>] Skipping Policy Group '{src_gname}': "
					f"Policy Group criteria references an IP-based Application Segment."
				)
				mt_stats["groups_filtered"] += 1
				continue

			# Fetch, hydrate, and validate Rules inside this Policy Group
			log.info(
				f"[Policy Group Sync] [Source Microtenant: <{mt_name}>] Fetching and hydrating Rules in Policy Group '{src_gname}'..."
			)
			src_rules = tenant.get_policy_group_rules(
				source_group_set_id,
				src_gid,
				microtenant_id=mt_id,
				group_obj=src_group,
			)
			log.info(
				f"[Policy Group Sync] [Source Microtenant: <{mt_name}>] Validating {len(src_rules)} Rule(s) in Policy Group "
				f"'{src_gname}' ({len(group_app_segments)} App Segment(s) in Policy Group)..."
			)

			valid_rules = []
			segments_to_share = dict(group_app_segments)
			has_valid_rule_app = False

			for rule in src_rules:
				r_name = rule.get("name", "<unnamed>")
				rule_app_segments = tenant.get_application_segments_in_object(
					rule, known_app_segments_by_id, is_group=False
				)

				if any(app_id in ip_segment_ids for app_id in rule_app_segments):
					log.warning(
						f"[Policy Group Sync] [Source Microtenant: <{mt_name}>]   Skipping Rule '{r_name}' in "
						f"'{src_gname}': rule criteria references an IP-based Application Segment."
					)
					mt_stats["rules_filtered"] += 1
					continue

				# Rule is valid if an Application Segment exists in EITHER the Policy Group OR the Rule
				if len(group_app_segments) == 0 and len(rule_app_segments) == 0:
					log.warning(
						f"[Policy Group Sync] [Source Microtenant: <{mt_name}>]   Skipping Rule '{r_name}' in "
						f"'{src_gname}': no Application Segments in either Policy Group or Rule."
					)
					mt_stats["rules_filtered"] += 1
					continue

				if len(rule_app_segments) > 0:
					has_valid_rule_app = True
				segments_to_share.update(rule_app_segments)
				valid_rules.append(rule)

			# Sync the Policy Group if a valid Application Segment exists in EITHER the Policy Group OR its valid Rules
			has_valid_group_app = len(group_app_segments) > 0
			if not (has_valid_group_app or has_valid_rule_app):
				log.info(
					f"[Policy Group Sync] [Source Microtenant: <{mt_name}>] Filtering out Policy Group '{src_gname}': "
					f"no valid Application Segments exist in either the Policy Group or its Rules "
					f"(source Rules: {len(src_rules)}, valid Rules: {len(valid_rules)})."
				)
				mt_stats["groups_filtered"] += 1
				continue

			log.info(
				f"[Policy Group Sync] [Source Microtenant: <{mt_name}>] Verifying/sharing {len(segments_to_share)} "
				f"referenced Application Segment(s) for '{target_group_name}' with Target <{target_microtenant}>..."
			)
			unshareable_app_ids = set()
			for app_id, app_name in segments_to_share.items():
				ok = tenant.ensure_segment_shared_with_target(
					app_id=app_id,
					app_name=app_name,
					source_mt_id=mt_id,
					source_mt_name=mt_name,
					target_mt_id=target_microtenant_id,
					target_mt_name=target_microtenant,
					mt_app_segments_by_id=mt_app_segments_by_id,
					default_app_segments_by_id=default_app_segments_by_id,
					target_visible_app_ids=target_visible_app_ids,
				)
				if not ok:
					unshareable_app_ids.add(str(app_id))

			if any(aid in unshareable_app_ids for aid in group_app_segments):
				log.error(
					f"[Policy Group Sync] [Source Microtenant: <{mt_name}>] Skipping Policy Group '{target_group_name}': "
					f"Policy Group Application Segment(s) {unshareable_app_ids & set(group_app_segments)} "
					f"could not be shared to Target."
				)
				mt_stats["groups_filtered"] += 1
				mt_stats["rules_filtered"] += len(valid_rules)
				continue

			if unshareable_app_ids:
				pre_filter_count = len(valid_rules)
				valid_rules = [
					r
					for r in valid_rules
					if not (
						set(tenant.get_application_segments_in_object(r, known_app_segments_by_id, is_group=False).keys())
						& unshareable_app_ids
					)
				]
				mt_stats["rules_filtered"] += pre_filter_count - len(valid_rules)
				remaining_rule_has_app = any(
					len(tenant.get_application_segments_in_object(r, known_app_segments_by_id, is_group=False)) > 0
					for r in valid_rules
				)
				if not (has_valid_group_app or remaining_rule_has_app):
					log.info(
						f"[Policy Group Sync] [Source Microtenant: <{mt_name}>] Skipping Policy Group '{target_group_name}': "
						f"no shareable Application Segments remain in Policy Group or Rules."
					)
					mt_stats["groups_filtered"] += 1
					continue

			# Step A: Create or Update Target Custom Policy Group (syncing groupCriteria if changed)
			log.info(
				f"[Policy Group Sync] [Source Microtenant: <{mt_name}>] Step A: Synchronizing Custom Policy Group "
				f"'{target_group_name}' and groupCriteria in Target <{target_microtenant}>..."
			)
			target_group_id = None
			matched_target_group_obj = None
			group_action_label = "Created"

			for candidate in synced_target_groups_pool:
				cmp_grp = tenant.compare_policy_group(src_group, candidate, target_group_name)
				if cmp_grp == 2:
					target_group_id = str(candidate["id"])
					matched_target_group_obj = candidate
					matched_target_group_ids.add(target_group_id)
					mt_stats["groups_unchanged"] += 1
					group_action_label = "Unchanged"
					log.info(
						f"[Policy Group Sync] [Source Microtenant: <{mt_name}>] Policy Group '{target_group_name}' "
						f"({target_group_id}) groupCriteria and metadata unchanged."
					)
					break
				elif cmp_grp == 1:
					target_group_id = str(candidate["id"])
					matched_target_group_obj = candidate
					matched_target_group_ids.add(target_group_id)
					mt_stats["groups_updated"] += 1
					group_action_label = "Updated"
					log.info(
						f"[Policy Group Sync] [Source Microtenant: <{mt_name}>] Updating Policy Group "
						f"'{target_group_name}' ({target_group_id}) because groupCriteria or metadata changed..."
					)
					tenant.update_policy_group(
						target_group_set_id,
						target_group_id,
						src_group,
						target_group_name,
						microtenant_id=target_microtenant_id,
						custom_type_template=custom_type_template,
						existing_target_group=candidate,
					)
					matched_target_group_obj = (
						tenant.get_policy_group(
							target_group_set_id, target_group_id, microtenant_id=target_microtenant_id
						)
						or candidate
					)
					break

			if target_group_id is None:
				log.info(
					f"[Policy Group Sync] [Source Microtenant: <{mt_name}>] Creating new Custom Policy Group "
					f"'{target_group_name}' in Target <{target_microtenant}>..."
				)
				created_grp = tenant.add_policy_group(
					target_group_set_id,
					src_group,
					target_group_name,
					microtenant_id=target_microtenant_id,
					custom_type_template=custom_type_template,
				)
				if not created_grp or "id" not in created_grp:
					log.error(
						f"[Policy Group Sync] [Source Microtenant: <{mt_name}>] Failed to create Policy Group "
						f"'{target_group_name}'; skipping its rules."
					)
					continue
				target_group_id = str(created_grp["id"])
				matched_target_group_obj = created_grp
				matched_target_group_ids.add(target_group_id)
				mt_stats["groups_created"] += 1
				group_action_label = "Created"

			desired_synced_groups_in_order.append((target_group_id, target_group_name, mt_name))

			# Step B: Synchronize all associated Rules & policyCriteria inside this Policy Group
			log.info(
				f"[Policy Group Sync] [Source Microtenant: <{mt_name}>] Step B: Synchronizing {len(valid_rules)} "
				f"associated Rule(s) and policyCriteria into Target Policy Group '{target_group_name}'..."
			)
			rule_stats = sync_rules_within_group(
				tenant=tenant,
				target_group_set_id=target_group_set_id,
				target_group_id=target_group_id,
				target_group_name=target_group_name,
				valid_source_rules=valid_rules,
				microtenant_name=mt_name,
				target_mt_id=target_microtenant_id,
				target_policy_set_id=target_policy_set_id,
				source_group_set_id=source_group_set_id,
				source_group_id=src_gid,
				inherited_group_app_ids=list(group_app_segments.keys()),
				target_group_obj=matched_target_group_obj,
			)

			mt_stats["rules_created"] += rule_stats["rules_created"]
			mt_stats["rules_updated"] += rule_stats["rules_updated"]
			mt_stats["rules_unchanged"] += rule_stats["rules_unchanged"]
			mt_stats["rules_deleted"] += rule_stats["rules_deleted"]

			synced_group_details.append(
				{
					"target_group_id": target_group_id,
					"target_group_name": target_group_name,
					"source_mt_name": mt_name,
					"group_action": group_action_label,
					"rule_stats": rule_stats,
				}
			)

		log.info(
			f"[Policy Group Sync] [Source Microtenant: <{mt_name}>] Completed Policy Group and Rule processing for <{mt_name}>."
		)

	# Step 5: Remove orphaned/filtered-out synced Policy Groups (and their rules) from Target
	log.info(
		f"[Policy Group Sync] Step 5: Checking {len(synced_target_groups_pool)} previously synced Policy Group(s) "
		f"in Target <{target_microtenant}> for obsolete/orphaned groups to remove..."
	)
	for candidate in synced_target_groups_pool:
		cand_id = str(candidate.get("id", ""))
		cand_name = candidate.get("name", "")
		if cand_id and cand_id not in matched_target_group_ids and cand_id not in target_protected_gids:
			cand_mt_name = cand_name.split(" - ", 1)[0] if " - " in cand_name else "Unknown"
			cand_mt_stats = _get_mt_stats(cand_mt_name)

			log.info(
				f"[Policy Group Sync] [Source Microtenant: <{cand_mt_name}>] Removing obsolete/filtered Policy Group "
				f"'{cand_name}' ({cand_id}) and its Rules from Target <{target_microtenant}>..."
			)
			orphan_rules = tenant.get_policy_group_rules(
				target_group_set_id, cand_id, microtenant_id=target_microtenant_id, group_obj=candidate
			)
			for o_rule in orphan_rules:
				if "id" in o_rule:
					log.info(
						f"[Policy Group Sync] [Source Microtenant: <{cand_mt_name}>]   - Deleting Rule "
						f"'{o_rule.get('name')}' from obsolete Policy Group '{cand_name}'."
					)
					tenant.delete_policy_group_rule(
						target_group_set_id, cand_id, o_rule["id"], microtenant_id=target_microtenant_id
					)
					cand_mt_stats["rules_deleted"] += 1

			tenant.delete_policy_group(target_group_set_id, cand_id, microtenant_id=target_microtenant_id)
			cand_mt_stats["groups_deleted"] += 1

	# Step 6: Align Custom Policy Group evaluation order starting at 2 (after Global Policy Group at order 1)
	log.info(
		f"[Policy Group Sync] Step 6: Aligning evaluation order for {len(desired_synced_groups_in_order)} "
		f"synced Custom Policy Group(s) in Target <{target_microtenant}>..."
	)
	refreshed_groups = tenant.get_all_policy_groups(
		target_group_set, microtenant_id=target_microtenant_id, hydrate_details=False
	)
	current_group_orders = {
		str(g["id"]): str(g.get("groupOrder") or g.get("order") or "")
		for g in refreshed_groups
		if isinstance(g, dict) and "id" in g
	}

	base_order = first_custom_order + len(local_target_custom_groups)
	for offset, (grp_id, grp_name, src_mt_name) in enumerate(desired_synced_groups_in_order):
		desired_order = base_order + offset
		if current_group_orders.get(grp_id) != str(desired_order):
			log.info(
				f"[Policy Group Sync] [Source Microtenant: <{src_mt_name}>] Reordering Policy Group "
				f"'{grp_name}' ({grp_id}) to groupOrder {desired_order}."
			)
			tenant.reorder_policy_group(
				target_group_set_id, grp_id, desired_order, microtenant_id=target_microtenant_id
			)
		else:
			log.info(
				f"[Policy Group Sync] [Source Microtenant: <{src_mt_name}>] Policy Group '{grp_name}' "
				f"({grp_id}) already at groupOrder {desired_order}."
			)

	# Step 7: Log Final Per-Microtenant & Per-Group Summary Tables
	log_final_summary_tables(
		target_microtenant=target_microtenant,
		preserved_local_group_count=len(local_target_custom_groups),
		mt_order=mt_order,
		mt_stats_by_name=mt_stats_by_name,
		synced_group_details=synced_group_details,
		base_group_order=base_order,
	)

	log.info("[Policy Group Sync] Synchronization complete.")


def main():
	sync()


if __name__ == "__main__":
	main()

