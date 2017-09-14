# -*- coding: utf-8 -*-

import six
import yara_validator as yaravalidator
import re

if six.PY3:
    import io
else:
    import StringIO as io

try:
    from pymisp import PyMISP, PyMISPError, MISPAttribute
    HAS_PYMISP = True
except ImportError:
    HAS_PYMISP = False


FILENAME_TAG = '@yara-filename:'


class _YaraMISPAttribute(MISPAttribute):  # FIXME  will fail is pymisp is not present

    def __init__(self, misp_attribute=None, **kwargs):
        if misp_attribute:
            if not isinstance(misp_attribute, MISPAttribute):
                raise TypeError("_YaraMISPAttribute's constructor expects misp_attribute to be MISPAttribute, or None")
        MISPAttribute.__init__(self)
        if misp_attribute and kwargs:
            values = misp_attribute.__dict__.copy()
            values.update(kwargs)
        elif misp_attribute:
            values = misp_attribute.__dict__
        elif kwargs:
            values = kwargs
        else:
            values = None
        if values:
            self.set_all_values(**values)

    def __str__(self):
        return self.yara_source

    @property
    def yara_source(self):
        return self.value

    @property
    def yara_incl_namespace(self):
        return str(self.event_id)

    @property
    def yara_incl_name(self):
        if self.comment:
            regex = re.compile(r'^\s*'+FILENAME_TAG+'(.*)$', re.MULTILINE)
            match = regex.search(self.comment)
            return match.group(1).strip() if match else None
        else:
            return None


class YaraMISP:
    # Note on naming conventions: 'attribute' represents a misp attribute (object) of type 'yara'
    #                             'rule' represents a yara signature (string) or set of signatures (as a single string)

    @classmethod
    def _fetch_yara_attrs(cls, server, key, enforce_ids, include=None, exclude=None):
        if not HAS_PYMISP:
            raise Exception("PyMISP is required by this module. Try 'pip install PyMISP'")
        misp = PyMISP(server, key, True, 'json')
        yara_dict_attrs = []
        yara_pymisp_attrs = []
        if not include:
            search_results = misp.search(controller='attributes', type_attribute='yara', to_ids=enforce_ids)
            if 'errors' in search_results:
                raise PyMISPError(search_results['message'])
            if search_results['response'] and search_results['response']['Attribute']:
                yara_dict_attrs = search_results['response']['Attribute']
        else:
            for evt_id in include:
                search_results = misp.search(controller='attributes', type_attribute='yara', to_ids=enforce_ids, eventid=evt_id)
                if 'errors' in search_results:
                    raise PyMISPError(search_results['message'])
                if search_results['response'] and search_results['response']['Attribute']:
                    yara_dict_attrs.append(search_results['response']['Attribute'])
        for attr in yara_dict_attrs:
            if not exclude or (attr['event_id'] not in exclude):
                misp_attribute = _YaraMISPAttribute(**attr)
                yara_pymisp_attrs.append(misp_attribute)
        return yara_pymisp_attrs

    @classmethod
    def check_all(cls, **kwargs):
        if not HAS_PYMISP:
            raise Exception("PyMISP is required by this module. Try 'pip install PyMISP'")
        attributes = kwargs['attributes'] if 'attributes' in kwargs else None
        server = kwargs['server'] if 'server' in kwargs else ''
        key = kwargs['key'] if 'key' in kwargs else None
        exclude_evts = kwargs['exclude_evts'] if 'exclude_evts' in kwargs else []
        include_evts = kwargs['include_evts'] if 'include_evts' in kwargs else []
        enforce_ids = kwargs['enforce_ids'] if 'enforce_ids' in kwargs else True
        if (not attributes and not (server and key)) or (attributes and server and key):
            raise Exception('yara_misp.check_all() requires either ("attributes") \
                            or ("server" and "key") parameter(s) but not both')
        if not attributes:
            raw_yara_attributes_buffer = cls._fetch_yara_attrs(server, key, enforce_ids, include=include_evts, exclude=exclude_evts)
        else:
            raw_yara_attributes_buffer = []
            for attr in attributes:
                if (not exclude_evts or attr.event_id not in exclude_evts)\
                        and (not include_evts or attr.event_id not in include_evts):
                    raw_yara_attributes_buffer.append(_YaraMISPAttribute(attr))

        yara_validator = yaravalidator.YaraValidator(auto_clear=False)
        for attr in raw_yara_attributes_buffer:
            yara_validator.add_rule_source(attr.yara_source,
                                           attr.yara_incl_namespace,
                                           attr.yara_incl_name)
        valid, broken, repaired = yara_validator.check_all()

        return valid, broken, repaired