# Copyright 2012 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# All Rights Reserved.
#
# Copyright 2012 Nebula, Inc.
# Copyright (c) 2012 X.commerce, a business unit of eBay Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from django.utils.translation import ugettext_lazy as _

from horizon import exceptions
from horizon import forms
from horizon import messages

from openstack_dashboard import api
from openstack_dashboard.usage import quotas
from horizon.utils import validators
from openstack_dashboard.api import base
from openstack_dashboard.api import openstackcli

class DeleteForwardingView(forms.SelfHandlingForm):
    failure_url = 'horizon:project:floating_ips:index'

    forward = forms.ThemableChoiceField(
                                  label=_("Port Forwarding"),
                                  help_text=_('Port Forwarding'))

    def __init__(self, request, *args, **kwargs):
        super(DeleteForwardingView, self).__init__(request, *args, **kwargs)
        param={}

        if request.user.token.id:
                param['token_id']=request.user.token.id
        if request.user.project_id:
                param['project_id']=request.user.project_id
        if request.user.id:
                param['user_id']=request.user.id
        endpoint=base.url_for(request, 'identity')
        if endpoint:
                param['endpoint']=endpoint
        if request.user.user_domain_name:
                param['user_domain_name']=request.user.user_domain_name
        if self.initial['id']:
                param['id'] = self.initial['id']
        vjson=openstackcli.floating_ip_port_forwarding_list(param)

        choices = []
        for var in vjson:
          choices.append((var['ID'], 
                         str(var['External Port']) +'(' + var['Protocol'] + ') -- '  + var['Internal IP Address'] + ':' + str(var['Internal Port'])))
        self.fields['forward'].choices = choices


    def get_ports(self, request):
        ports = self.initial['ports']
        return [(p, p) for p in ports]

    def handle(self, request, data):
        port_id = self.initial['id']
        name_or_id = data.get('name') or port_id

        param={}
        if request.user.token.id:
                param['token_id']=request.user.token.id
        if request.user.project_id:
                param['project_id']=request.user.project_id
        if request.user.id:
                param['user_id']=request.user.id
        endpoint=base.url_for(request, 'identity')
        if endpoint:
                param['endpoint']=endpoint
        if request.user.user_domain_name:
                param['user_domain_name']=request.user.user_domain_name
        if self.initial['id']:
                param['id'] = self.initial['id']
        if data['forward']:
                param['forward'] = data['forward']
        vjson=openstackcli.floating_ip_port_forwarding_delete(param)
        puid=0
        if puid == 0:
                messages.success(request,
                             _('Deleted port forwarding: %(ip)s.')
                             % {"ip": param['forward']})
        else:
                exceptions.handle(request, _('Unable to delete port forwarding. %(ip)s.') % {"ip": param['forward']})
        return True


class ForwardingPort(forms.SelfHandlingForm):
    port_validator = validators.validate_port_or_colon_separated_port_range
    pool = forms.ThemableChoiceField(label=_("Floating IP"),
                                     help_text=_('Floating IP that the port forwarding belongs'))
    protocol = forms.ThemableChoiceField(
                                  label=_("Protocol"),
                                  choices=[('tcp', _('TCP')), ('udp', _('UDP'))],
                                  help_text=_('The protocol used in the floating IP port forwarding, for instance: TCP, UDP'))
    source_port = forms.CharField(
        max_length=5,
        label=_("External Port"),
        required=False,
        validators=[port_validator],
        help_text=_('The protocol port number of the port forwarding\'s floating IP address. Integer in [1, 65535]'))
    port = forms.ThemableChoiceField(label=_("Internal IP address"),
                                     help_text=_("""The fixed IPv4 address of the network port associated
                                                    to the floating IP port forwarding"""))
    dst_port = forms.CharField(
        max_length=5,
        label=_("Internal Port"),
        required=False,
        validators=[port_validator],
        help_text=_("""The protocol port number of the network port fixed IPv4 address associated to the floating IP port
                       forwarding. Integer in [1, 65535]"""))

    def __init__(self, request, *args, **kwargs):
        super(ForwardingPort, self).__init__(request, *args, **kwargs)
        floating_ip_list = kwargs.get('initial', {}).get('ip_list', [])
        self.fields['pool'].choices = floating_ip_list

        ports = []
        try:
            ports = api.neutron.port_list(request, device_owner=('compute:nova', 'Octavia'))
        except Exception:
            exceptions.handle(request, _('Unable to retrieve ports '
                                         'information.'))
        choices = []
        for port in ports:
            ips = []
            for ip in port.fixed_ips:
                ips.append(ip['ip_address'])
            choices.append((port.id, ','.join(ips) or port.id))
        if choices:
            choices.insert(0, ("", _("Select Port")))
        else:
            choices.insert(0, ("", _("No Ports available")))
        self.fields['port'].choices = choices


    def handle(self, request, data):
        try:
            param = {}
            if data['pool']:
                param['pool'] = data['pool']
            if data['protocol']:
                param['protocol'] = data['protocol']
            if data['source_port']:
                param['source_port'] = data['source_port']
            if data['port']:
                param['port'] = data['port']
                black_port = api.neutron.port_get(request,param['port'])
                param['portip'] = black_port.fixed_ips[0]['ip_address']
            if data['dst_port']:
                param['dst_port'] = data['dst_port']
            if request.user.token.id:
                param['token_id']=request.user.token.id
            if request.user.project_id:
                param['project_id']=request.user.project_id
            if request.user.id:
                param['user_id']=request.user.id
            endpoint=base.url_for(request, 'identity')
            if endpoint:
                param['endpoint']=endpoint
            if request.user.user_domain_name:
                param['user_domain_name']=request.user.user_domain_name
            vjson=openstackcli.floating_ip_port_forwarding_create(param)
            if vjson['internal_port_id'] == data['port']:
                messages.success(request,
                             _('Forwarding IP: %(ip)s.')
                             % {"ip": vjson['internal_ip_address']})
            else:
                exceptions.handle(request,
                                  _('Unable to Forwarding IP: %(ip)s.')
                                  % {"ip": param['portip']})
            return True
        except Exception:
            exceptions.handle(request, _('Unable to allocate Floating Port.'))


class FloatingIpAllocate(forms.SelfHandlingForm):
    pool = forms.ThemableChoiceField(label=_("Pool"))
    description = forms.CharField(max_length=255,
                                  label=_("Description"),
                                  required=False)
    dns_domain = forms.CharField(max_length=255,
                                 label=_("DNS Domain"),
                                 required=False)
    dns_name = forms.CharField(max_length=255,
                               label=_("DNS Name"),
                               required=False)

    def __init__(self, request, *args, **kwargs):
        super(FloatingIpAllocate, self).__init__(request, *args, **kwargs)
        floating_pool_list = kwargs.get('initial', {}).get('pool_list', [])
        self.fields['pool'].choices = floating_pool_list

        dns_supported = api.neutron.is_extension_supported(
            request,
            "dns-integration")
        if not dns_supported:
            del self.fields["dns_name"]
            del self.fields["dns_domain"]

    def handle(self, request, data):
        try:
            # Prevent allocating more IP than the quota allows
            usages = quotas.tenant_quota_usages(request,
                                                targets=('floatingip', ))
            if ('floatingip' in usages and
                    usages['floatingip']['available'] <= 0):
                error_message = _('You are already using all of your available'
                                  ' floating IPs.')
                self.api_error(error_message)
                return False

            param = {}
            if data['description']:
                param['description'] = data['description']
            if 'dns_domain' in data and data['dns_domain']:
                param['dns_domain'] = data['dns_domain']
            if 'dns_name' in data and data['dns_name']:
                param['dns_name'] = data['dns_name']
            fip = api.neutron.tenant_floating_ip_allocate(
                request,
                pool=data['pool'],
                **param)
            messages.success(request,
                             _('Allocated Floating IP %(ip)s.')
                             % {"ip": fip.ip})
            return fip
        except Exception:
            exceptions.handle(request, _('Unable to allocate Floating IP.'))
