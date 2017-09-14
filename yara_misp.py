# -*- coding: utf-8 -*-

import six
import yara_validator as yaravalidator
import re

from pymisp import PyMISP, PyMISPError, MISPAttribute
from yara_validator import YaraSource, YaraValidator


FILENAME_TAG = '@yara-filename:'


class YaraMISPAttribute(MISPAttribute, YaraSource):

    def __init__(self, misp_attribute=None, **kwargs):

        MISPAttribute.__init__(self)
        if (misp_attribute and kwargs) or (not misp_attribute and not kwargs):
            raise SyntaxError("YaraMISPAttribute's constructor expects either "
                              "misp_attribute or **kwargs to be set")
        elif misp_attribute:
            if isinstance(misp_attribute, MISPAttribute):
                self.set_all_values(misp_attribute.__dict__)
            else:
                raise TypeError("YaraMISPAttribute's constructor expects "
                                "misp_attribute to be MISPAttribute, or None")
        else:
            self.set_all_values(**kwargs)
        YaraSource.__init__(self,
                            source=self._yaramisp_source,
                            namespace=str(self.event_id),
                            include_name=self._yaramisp_include_name)

    @property
    def _yaramisp_source(self):
        # TODO move MISP export module's logic here
        return self.value

    @property
    def _yaramisp_include_name(self):
        if self.comment:
            regex = re.compile(r'^\s*'+FILENAME_TAG+'(.*)$', re.MULTILINE)
            match = regex.search(self.comment)
            return match.group(1).strip() if match else None
        else:
            return None

    def __str__(self):
        res = '// EVENT:     {}\n// ATTRIBUTE: {}\n'.format(self.event_id,
                                                         self.uuid)
        return res + YaraSource.__str__(self)


class YaraMISP:
    # Note on naming conventions:
    # 'attribute' represents a misp attribute (object) of type 'yara'
    # 'rule' represents a yara signature (string) or set of signatures

    @classmethod
    def _fetch_attrs(cls, server, key, enforce_ids, include=None, exclude=None):
        misp = PyMISP(server, key, True, 'json')
        yara_dict_attrs = []
        yara_pymisp_attrs = []
        if not include:
            search_results = misp.search(controller='attributes',
                                         type_attribute='yara',
                                         to_ids=enforce_ids)
            if 'errors' in search_results:
                raise PyMISPError(search_results['message'])
            if search_results['response'] \
                    and search_results['response']['Attribute']:
                yara_dict_attrs = search_results['response']['Attribute']
        else:
            for evt_id in include:
                search_results = misp.search(controller='attributes',
                                             type_attribute='yara',
                                             to_ids=enforce_ids,
                                             eventid=evt_id)
                if 'errors' in search_results:
                    raise PyMISPError(search_results['message'])
                if search_results['response'] \
                        and search_results['response']['Attribute']:
                    yara_dict_attrs.append(
                        search_results['response']['Attribute'])
        for attr in yara_dict_attrs:
            if not exclude or (attr['event_id'] not in exclude):
                misp_attribute = YaraMISPAttribute(**attr)
                yara_pymisp_attrs.append(misp_attribute)
        return yara_pymisp_attrs

    @classmethod
    def check_all(cls, **kwargs):
        attributes = kwargs['attributes'] if 'attributes' in kwargs else None
        server = kwargs['server'] if 'server' in kwargs else ''
        key = kwargs['key'] if 'key' in kwargs else None
        exclude_evts = kwargs['exclude_evts'] if 'exclude_evts' in kwargs \
            else []
        include_evts = kwargs['include_evts'] if 'include_evts' in kwargs \
            else []
        enforce_ids = kwargs['enforce_ids'] if 'enforce_ids' in kwargs \
            else True
        if (attributes and server and key) or \
                (not attributes and not (server and key)):
            raise Exception('yara_misp.check_all() requires either '
                            '("attributes") or ("server" and "key") '
                            'but not both')

        if not attributes:
            raw_yara_attributes_buffer = cls._fetch_attrs(server,
                                                          key,
                                                          enforce_ids,
                                                          include=include_evts,
                                                          exclude=exclude_evts)
        else:
            raw_yara_attributes_buffer = []
            for attr in attributes:
                if (not exclude_evts or attr.event_id not in exclude_evts) and \
                        (not include_evts or attr.event_id not in include_evts):
                    raw_yara_attributes_buffer.append(YaraMISPAttribute(attr))

        yara_validator = yaravalidator.YaraValidator(auto_clear=False)
        for attr in raw_yara_attributes_buffer:
            yara_validator.add_rule_source(attr)
        valid, broken, repaired = yara_validator.check_all()

        return valid, broken, repaired