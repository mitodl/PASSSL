from Products.Archetypes.Extensions.utils import install_subskin
from Products.CMFCore.utils import getToolByName
from Products.PluggableAuthService.interfaces.plugins import IAuthenticationPlugin, IExtractionPlugin
from Products.PASSSL.config import *
from StringIO import StringIO

def install( portal ):
    out = StringIO()

    install_subskin(portal, out, GLOBALS)

    pas = portal.acl_users
    registry = pas.plugins
    groupplugins = [id for id, pi in registry.listPlugins(IAuthenticationPlugin)]
    if 'credentials_passsl' not in groupplugins:
        factories = pas.manage_addProduct['PASSSL']    
        try:
             factories.manage_addSSLAuthHelper('credentials_passsl', 'SSLAuthHelper')
	except:
	     pass
        registry.activatePlugin(IAuthenticationPlugin, 'credentials_passsl' )
        registry.activatePlugin(IExtractionPlugin, 'credentials_passsl' )

    # install our portlet if it isn't there already

    left_slots = ["here/has_key_portlet/macros/portlet"]
    if left_slots[0] not in portal.left_slots:
	left_slots.extend(portal.left_slots)
	portal.left_slots = tuple(left_slots)


    pcp = portal.portal_controlpanel
    if pcp:
            pcp.addAction(
                id =          'passsl_cert_mapping',
                name =        'SSL User Certificate Mappings',
                action =      'string:${portal_url}/acl_users/credentials_passsl/edit_mappings',
                permission =  'Manage users',
	        appId = 'PASSSL',
                visible = 1)

    print >>out, "Installed PASSL."

    return out.getvalue()
 
def uninstall( portal ):
    try:
        pas = portal.acl_users
        registry = pas.plugins
        registry.deactivatePlugin(IAuthenticationPlugin, 'credentials_passsl')
        registry.deactivatePlugin(IExtractionPlugin, 'credentials_passsl')
        pcp = portal.portal_controlpanel
        pcp.unregisterApplication('PASSSL')
    except:
        pass
