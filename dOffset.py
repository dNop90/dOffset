#------------------------------------------------------------------------------
#   IDA Plugin
#   dOffset
#   
#   Go to offset or copy offset from current line
#------------------------------------------------------------------------------

VERSION = '1.0.0'
AUTHOR = 'dNop90'
PLUGIN_NAME = "dOffset"


import idc
import idaapi
import idautils
import PyQt5.QtGui as QtGui
import PyQt5.QtCore as QtCore
import PyQt5.QtWidgets as QtWidgets
from PyQt5.Qt import QApplication

class dOffset(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "Get current address offset or jump to specific offset"
    wanted_name = PLUGIN_NAME
    
    def init(self):
        self.AddActionGetOffset()
        self._init_hooks()
        
        print(f"[{PLUGIN_NAME}] Loaded")
        return idaapi.PLUGIN_KEEP
        
    def run(self, arg):
        pass
        
    def term(self):
        self.RemoveActionGetOffset()
        self._hooks.unhook()
        
    def _init_hooks(self):
        self._hooks = Hooks()
        self._hooks.ready_to_run = self._init_hexrays_hooks
        self._hooks.hook()

    def _init_hexrays_hooks(self):
        if idaapi.init_hexrays_plugin():
            idaapi.install_hexrays_callback(self._hooks.hxe_callback)
        
    ACTION_NAME_GETOFFSET = "dOffset:GetOffset"
    def AddActionGetOffset(self):
        action_desc = idaapi.action_desc_t(
            self.ACTION_NAME_GETOFFSET,
            "Get Offset",
            GetOffsetHandler(),
            "",
            "Get current line offset",
            0
        )
        idaapi.register_action(action_desc)
    
    def RemoveActionGetOffset(self):
        idaapi.unregister_action(self.ACTION_NAME_GETOFFSET)


def PLUGIN_ENTRY():
    return dOffset()
    
    
class Hooks(idaapi.UI_Hooks):
    def __init__(self):
        super(Hooks, self).__init__()

    def finish_populating_widget_popup(self, widget, popup):
        if idaapi.get_widget_type(widget) == idaapi.BWN_DISASMS:
            idaapi.attach_action_to_popup(
                widget,
                popup,
                dOffset.ACTION_NAME_GETOFFSET,
                "Get Offset",
                idaapi.SETMENU_APP
            ) 
        return 0
    
    def hxe_callback(self, event, *args):
        if event == idaapi.hxe_populating_popup:
            form, popup, vu = args
            
            if get_cursor_func_ref() == idaapi.BADADDR:
                return 0
                
            idaapi.attach_action_to_popup(
                form,
                popup,
                dOffset.ACTION_NAME_GETOFFSET,
                "Get Offset",
                idaapi.SETMENU_APP
            )
        
        return 0


#Action right click
class GetOffsetHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        
    def activate(self, ctx):
        CurrentOffset = idaapi.get_screen_ea() - idaapi.get_imagebase()
        
        clipboard = QApplication.clipboard()
        clipboard.clear(mode=clipboard.Clipboard )
        clipboard.setText(f'{CurrentOffset:X}', mode=clipboard.Clipboard)
        
        print(f"[{PLUGIN_NAME}] Offset: 0x{CurrentOffset:X}")
        return 1
    
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
