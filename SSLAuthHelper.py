##############################################################################
#
# Copyright (c) 2001 Zope Corporation and Contributors. All Rights
# Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this
# distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################
""" Class: SSLAuthHelper

$Id: SSLAuthHelper.py,v 1.24 2009/03/10 21:50:25 mengel Exp $
"""

from zExceptions import Unauthorized

from AccessControl import Permissions
from Products.PageTemplates.PageTemplateFile import PageTemplateFile



from AccessControl.SecurityInfo import ClassSecurityInfo
from App.class_init import default__class_init__ as InitializeClass

from OFS.Folder import Folder
from OFS.Cache import Cacheable


from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin

from Products.PluggableAuthService.utils import classImplements
from Products.PluggableAuthService.interfaces.plugins import IAuthenticationPlugin, IExtractionPlugin, IRolesPlugin

from Products.PluggableAuthService.plugins.CookieAuthHelper import CookieAuthHelper

from zLOG import LOG, INFO, ERROR, WARNING

import re

def manage_addSSLAuthHelper( dispatcher, id='credentials_passsl', title=None, REQUEST=None ):
    """ 
     Add a HTTP SSL Helper to a Pluggable Auth Service.
    """
    sp = SSLAuthHelper( id, title )
    dispatcher._setObject( sp.getId(), sp )

    if REQUEST is not None:
        REQUEST['RESPONSE'].redirect( '%s/manage_workspace'
                                      '?manage_tabs_message='
                                      'SSLAuthHelper+added.'
                                    % dispatcher.absolute_url() )




class SSLAuthHelper( BasePlugin ):

    """ Multi-plugin for managing details of HTTPS SSL auth
	Methods to add to GroupUserFolder to make ssl authentication
        work nicely, to wit:
        * You can log in as whoever
        * One can define a mapping from SSL specific user-certificate 
	  subject Distinguished Names  to *lists* of local users -- so
          you can let a particular key log in as "admin" as well as "fred".
	* One can define a regex translation from subject Distinguished
          Names to local user names for given Issuer Distinguished Names
	  So you can have one rule for everyone issued certificates by
          a given Certificate Authority.
        * One can get a list of what local users you can log in as
          with your current SSL certificate, so you can put it on 
          a login-related portlet.
    """
    meta_type = 'SSLAuthHelper'
    security = ClassSecurityInfo()
    __implements__ = (getattr(BasePlugin,'__implements__',()),)

    def __init__( self, id, title=None ):
        self._setId( id )
        self.title = title
        if not hasattr(self,'camap'):
	    self.camap = [ 
		    { 
			'i_dn': "/DC=gov/DC=fnal/O=Fermilab/OU=Certificate Authorities/CN=Kerberized CA",
			'regex':   ".*UID=(.*)",
			'repl': r"\1",
		    }
		]
	if not hasattr( self,'dnmap'):
	    self.dnmap = {
			'/DC=gov/DC=fnal/O=Fermilab/OU=People/CN=Marc W. Mengel/UID=mengel': 'mengel',
		    }
        if not hasattr(self,'auto_login_users_flag'):
		self.auto_login_users_flag =  0

    security.declarePrivate( 'extractCredentials' )
    def extractCredentials( self, request ):
	# mooch off cookie_auth...
        #LOG('SSLAuthHelper',INFO,'Enter extractCred...')
        ca = getattr(self,'credentials_cookie_auth',getattr(self,'cookie_auth',None))
        #LOG('SSLAuthHelper',INFO,'got ca of ' + str(ca))
        if ca: 
            creds = ca.extractCredentials(request)
            #LOG('SSLAuthHelper',INFO,'ca give us' + repr(creds))
        else:
            creds = {}
        creds['scsdn'] = request.get_header('HTTP_X_S_DN')
        creds['scidn'] = request.get_header('HTTP_X_I_DN')
        if creds['scsdn'] == None and creds['scidn'] == None:
            creds['scsdn'] = request.get_header('SSL_CLIENT_S_DN')
            creds['scidn'] = request.get_header('SSL_CLIENT_I_DN')

	# try auto-login...
	if creds.get('login',None) == None and self.auto_login_users_flag:
	    usermap = self.mapped_users_2(creds['scsdn'], creds['scidn'])
	    #LOG('SSLAuthHelper',INFO,'autologin: ' + repr(usermap))
	    if len(usermap) == 1:
                #LOG('SSLAuthHelper',INFO,'autologin ' + usermap.keys()[0])
		creds['login'] = usermap.keys()[0]
		# creds['password'] = ''

        #LOG('SSLAuthHelper',INFO,'extractCred...' + repr(creds))
        return creds

    security.declarePrivate('authenticateCredentials')
    def authenticateCredentials(self, credentials):
        """ Fulfill AuthenticationPlugin requirements """
        login = credentials.get('login', '')
        scsdn = credentials.get('scsdn','')
        scidn = credentials.get('scidn','')
        usermap = self.mapped_users_2(scsdn, scidn)
        user = usermap.get(login, None)
        #LOG('SSLAuthHelper',INFO,'authenticateCred... cred' + repr(credentials) + ' user '+ repr(user))
        if user:
            return (login,login)
        else:
            return (None,None)

    security.declareProtected(Permissions.manage_users, "ssl_auth_getmaps" )
    def ssl_auth_getmaps(self):
        return (self.camap, self.dnmap)

    security.declareProtected(Permissions.manage_users, "ssl_auth_addcamap" )
    def ssl_auth_addcamap(self, i_dn, regex, repl):
        #LOG('SSLAuthHelper',INFO,'Entering ssl_auth_addcamap')
        self.camap.append( 
            { 
                'i_dn':  i_dn,
                'regex': regex,
                'repl':  repl,
            })
        self.camap = self.camap
        if hasattr(self,'_v_mapcache'):
            self._v_mapcache = {}



    security.declareProtected(Permissions.manage_users, "ssl_auth_delcamap" )
    def ssl_auth_delcamap(self, list):
        #LOG('SSLAuthHelper',INFO,'Entering ssl_auth_delcamap')
        for item in list:
            lst = item.split('+',1)
            i_dn = lst[0]
	    rest = lst[1]
	    (regex, user) = rest.rsplit('+',1)
            #(i_dn, regex, user) = item.split('+')
            for i in range(0,len(self.camap)):
                if ( self.camap[i]['i_dn'] == i_dn  and 
                        self.camap[i]['regex'] == regex  and 
                        self.camap[i]['repl'] == user ):
                    del self.camap[i]
                    break
        self.camap = self.camap
        if hasattr(self,'_v_mapcache'):
            self._v_mapcache = {}


    security.declareProtected(Permissions.manage_users, "ssl_auth_adddnmap" )
    def ssl_auth_adddnmap(self, s_dn, user):
        #LOG('SSLAuthHelper',INFO,'Entering ssl_auth_adddnmap ')

        # clean up input -- people cut and paste whitespace on the dn
        # and invalid usernames cause woes...
        s_dn = s_dn.strip()
        user = re.sub('[^\w,]','',user)

        current = self.dnmap.get(s_dn, None)
        if current != None:
            keys = current.split(',')
            newkeys = user.split(',')
            keymap = {}
            for u in keys:
                keymap[u] = 1
            for u in newkeys:
                keymap[u] = 1
            if not user in keys:
                self.dnmap[s_dn] = ','.join(keymap.keys())
        else:
            self.dnmap[s_dn] = user
        self.dnmap = self.dnmap
        if hasattr(self,'_v_mapcache'):
            self._v_mapcache = {}


    security.declareProtected(Permissions.manage_users, "ssl_auth_deldnmap" )
    def ssl_auth_deldnmap(self, list):
        #LOG('SSLAuthHelper',INFO,'Entering ssl_auth_delnmap')
        for item in list:
            (s_dn, userlist) = item.split('+')
            if self.dnmap[s_dn] == userlist:
                del self.dnmap[s_dn]
        self.dnmap = self.dnmap
        if hasattr(self,'_v_mapcache'):
            self._v_mapcache = {}


    def ssl_auth_get_mapped_users(self, request):
        return self.mapped_users(request).keys()

    def ssl_auth_get_auto_login_users_flag(self):
        return self.auto_login_users_flag

    def ssl_auth_set_auto_login_users_flag(self, value):
        self.auto_login_users_flag = value

    def old_modifyRequest(self, container, request):
 
        if not request[ 'REQUEST_METHOD' ] in ( 'GET', 'PUT', 'POST' ):
            return

        if self.auto_login_users_flag and (request.environ.get('HTTPS','') != "" or request.get("HTTP_X_S_DN","") != ""):

             name_list = self.ssl_auth_get_mapped_users(request)


             if len(name_list) == 1:

                # only auto-login if just one name is mapped, and
                # they're not already authenticated some other way

                user = self.getUser(name_list[0])
                if user and not getattr(request, '_cookie_auth',0) and not request._auth:
                    request._auth = 'basic '+encodestring(name_list[0]+':')
                    request['RESPONSE']._auth = 1

    def mapped_users(self,request):

        # allow either the proxy header approach, or the 
        # proxy-with-headers approach to work
        scsdn = request.get('HTTP_X_S_DN')
        scidn = request.get('HTTP_X_I_DN')
        if scsdn == None and scidn == None:
            scsdn = request.environ.get('SSL_CLIENT_S_DN')
            scidn = request.environ.get('SSL_CLIENT_I_DN')
        return self.mapped_users_2(scsdn,scidn)

    def mapped_users_2(self,scsdn, scidn):

	#LOG('SSLAuthHelpder',INFO,'starting mapped_users_2')
	if not hasattr(self,'_v_mapcache'):
	    self._v_mapcache = {}

	if self._v_mapcache.has_key(scsdn):
            return self._v_mapcache[scsdn]

        name_list = {}

        scsuid_list_str = self.dnmap.get(scsdn,'')
        if scsuid_list_str:
            scsuid_list = scsuid_list_str.split(',')
            for scsuid in scsuid_list:
                user = self.getUser(scsuid)
                if user != None:
                    name_list[scsuid] = user

	#LOG('SSLAuthHelpder',INFO,'camap = ' + repr(self.camap))
        for dict in self.camap:
            if scidn == dict['i_dn']:
                if re.match(dict['regex'], scsdn):
                    scsuid_list_str = re.sub(dict['regex'],dict['repl'],scsdn)
                    scsuid_list = scsuid_list_str.split(',')
                    for scsuid in scsuid_list:
                            user = self.getUser(scsuid)
                            if user != None:
                                name_list[scsuid] = user
	self._v_mapcache[scsdn] = name_list
        return name_list

    security.declareProtected(Permissions.manage_users, 'zope_edit_mappings')
    zope_edit_mappings = PageTemplateFile('skins/PASSSL/zope_edit_mappings',globals())
    manage_options = ( 
                      BasePlugin.manage_options +
                      Cacheable.manage_options +
			( { 'label' : 'SSL Mappings'
                          , 'action': 'zope_edit_mappings' }
                        ,
                        ) 
                      )

    security.declareProtected(Permissions.manage_users, 'manage_updateMappings')
    def manage_updateMappings(self, REQUEST=None, **kwargs):
	""" handle update form..."""

	r = REQUEST
	au = self
	change = r.get('change')

	if change == 'update_password':
	    au.ssl_auth_set_auto_login_users_flag(r.get('auto_login_users_flag',None))

	if change == 'camap':
	    au.ssl_auth_addcamap(r.get('i_dn'), r.get('regex'), r.get('user'))

	if change == 'del_camap':
	    au.ssl_auth_delcamap( r.get('deleteme'))

	if change == 'dnmap':
	    au.ssl_auth_adddnmap(r.get('s_dn'), r.get('user'))

	if change == 'del_dnmap':
	    au.ssl_auth_deldnmap(r.get('deleteme'))

	if r.get('URL').find('manage_updateMappings') >= 0:
	    REQUEST['RESPONSE'].redirect(self.absolute_url()+'/zope_edit_mappings')


    def getRolesForPrincipal(self, user, request=None):
        """ Set roles for whether we have a certificate, etc... """

        if request == None:
            return

	roles = []

        scsdn = request.get('HTTP_X_S_DN', '')

        if (scsdn != ''):
            roles.append('Certified')

        netlist = request.get('HTTP_X_FORWARDED_FOR',
			request.get('REMOTE_ADDR','')).split('.')

        if (len(netlist) == 4):
	    roles.append('NET_1_%s' % netlist[0])
	    roles.append('NET_2_%s_%s' % (netlist[0],netlist[1]))
	    roles.append('NET_3_%s_%s_%s' % (netlist[0],netlist[1],netlist[2]))

	return tuple(roles)
        
        
classImplements(SSLAuthHelper,IAuthenticationPlugin, IExtractionPlugin, IRolesPlugin)

InitializeClass( SSLAuthHelper )
