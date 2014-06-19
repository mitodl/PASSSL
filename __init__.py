"""
installer for PAS plugin...
"""
from AccessControl.Permissions import add_user_folders
from Products.PluggableAuthService.PluggableAuthService import registerMultiPlugin
from SSLAuthHelper import SSLAuthHelper, manage_addSSLAuthHelper
from zLOG import LOG, INFO, ERROR, WARNING
try:
    from Products.CMFCore.DirectoryView import registerDirectory
    registerDirectory('skins', globals())
except:
    pass

def initialize(context):
    """ Initialize the SSLAuthHelper """

    try:
        registerMultiPlugin(SSLAuthHelper.meta_type)
    except:
        pass

    context.registerClass( SSLAuthHelper
		     , permission=add_user_folders
		     , constructors=( manage_addSSLAuthHelper
				    , manage_addSSLAuthHelper
				    )
		     , icon='www/ssl.png'
		     , visibility=None
		     )
