## Controlled Python Script 'update_maps'
##bind container=container
##bind context=context
##bind namespace=
##bind subpath=traverse_subpath
##title=Update a FormulatorData object

r = context.REQUEST
try:
    context.manage_updateMappings(REQUEST=r)

    state.set(status='success', next_action='traverse_to:string:edit_mappings')
except:
    state.set(status='failed', next_action='traverse_to:string:edit_mappings')

return state
