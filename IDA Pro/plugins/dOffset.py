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
import PyQt5.QtGui as QtGui
import PyQt5.QtCore as QtCore
import PyQt5.QtWidgets as QtWidgets
from PyQt5.Qt import QApplication

class dOffset(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "Get current address offset or jump to specific offset"
    wanted_name = PLUGIN_NAME
    
    def init(self):
        self.AddActions()
        self._init_hooks()
        
        print(f"[{PLUGIN_NAME}] Loaded")
        return idaapi.PLUGIN_KEEP
        
    def run(self, arg):
        pass
        
    def term(self):
        self.RemoveAllActions()
        self._hooks.unhook()
        
    def _init_hooks(self):
        self._hooks = Hooks()
        self._hooks.ready_to_run = self._init_hexrays_hooks
        self._hooks.hook()

    def _init_hexrays_hooks(self):
        if idaapi.init_hexrays_plugin():
            idaapi.install_hexrays_callback(self._hooks.hxe_callback)
        
    ACTION_NAME_MAINCTX = "dOffset"
    ACTION_NAME_GETOFFSET = "dOffset:GetOffset"
    ACTION_NAME_GETMODULEWITHOFFSET = "dOffset:GetModuleWithOffset"
    ACTION_NAME_JUMPTOOFFSET = "dOffset:JumpToOffset"
    def AddActions(self):
        action_desc_offset = idaapi.action_desc_t(
            self.ACTION_NAME_GETOFFSET,
            "Get offset",
            GetOffsetHandler(),
            None,
            "Get current address offset"
        )
        action_desc_module_offset = idaapi.action_desc_t(
            self.ACTION_NAME_GETMODULEWITHOFFSET,
            "Get module name + offset",
            GetModuleOffsetHandler(),
            None,
            "Get current module name with current address offset"
        )
        action_desc_jump_offset = idaapi.action_desc_t(
            self.ACTION_NAME_JUMPTOOFFSET,
            "Jump to offset",
            JumpToOffsetHandler(),
            None,
            "Jump to address offset"
        )

        idaapi.register_action(action_desc_offset)
        idaapi.register_action(action_desc_module_offset)
        idaapi.register_action(action_desc_jump_offset)

        self.AttachActionToMenu()

    def AttachActionToMenu(self):
        idaapi.attach_action_to_menu(
            "Jump/dOffset/",
            self.ACTION_NAME_JUMPTOOFFSET,
            idaapi.SETMENU_APP
        )
    
    def RemoveAllActions(self):
        idaapi.unregister_action(self.ACTION_NAME_GETOFFSET)
        idaapi.unregister_action(self.ACTION_NAME_GETMODULEWITHOFFSET)
        idaapi.unregister_action(self.ACTION_NAME_JUMPTOOFFSET)


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
                dOffset.ACTION_NAME_MAINCTX,
                "dOffset",
                idaapi.SETMENU_APP
            )
            idaapi.attach_action_to_popup(
                widget,
                popup,
                dOffset.ACTION_NAME_GETOFFSET,
                dOffset.ACTION_NAME_MAINCTX + "/"
            )
            idaapi.attach_action_to_popup(
                widget,
                popup,
                dOffset.ACTION_NAME_GETMODULEWITHOFFSET,
                dOffset.ACTION_NAME_MAINCTX + "/"
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
                dOffset.ACTION_NAME_MAINCTX,
                "dOffset",
                idaapi.SETMENU_APP
            )
            idaapi.attach_action_to_popup(
                form,
                popup,
                dOffset.ACTION_NAME_GETOFFSET,
                dOffset.ACTION_NAME_MAINCTX + "/"
            )
            idaapi.attach_action_to_popup(
                form,
                popup,
                dOffset.ACTION_NAME_GETMODULEWITHOFFSET,
                dOffset.ACTION_NAME_MAINCTX + "/"
            )
        
        return 0


#Action Handlers
class GetOffsetHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        
    def activate(self, ctx):
        CurrentOffset = idaapi.get_screen_ea() - idaapi.get_imagebase()
        
        clipboard = QApplication.clipboard()
        clipboard.clear(mode=clipboard.Clipboard )
        clipboard.setText(f'{CurrentOffset:X}', mode=clipboard.Clipboard)
        
        print("[%s] %X -> 0x%X" % (PLUGIN_NAME, idaapi.get_screen_ea(), CurrentOffset))
        return 1
    
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
    
class GetModuleOffsetHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        
    def activate(self, ctx):
        CurrentOffset = idaapi.get_screen_ea() - idaapi.get_imagebase()
        file_name = idc.get_root_filename()
        
        clipboard = QApplication.clipboard()
        clipboard.clear(mode=clipboard.Clipboard )
        clipboard.setText(f'{file_name}+{CurrentOffset:X}', mode=clipboard.Clipboard)
        
        print("[%s] %X -> %s+0x%X" % (PLUGIN_NAME, idaapi.get_screen_ea(), file_name, CurrentOffset))
        return 1
    
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
    
class JumpToOffsetHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        
    def activate(self, ctx):
        InputOffset = idaapi.ask_str("", 0, "Offset:")
        if (InputOffset is None):
            return 1
        
        if "0x" in InputOffset:
            InputOffset = InputOffset.replace("0x", "")

        if(not is_hex(InputOffset)):
            print("[%s] Invalid offset value %s" % (PLUGIN_NAME, InputOffset))
            return 1
        
        InputOffsetInt = int(InputOffset.lower(), 16)
        AddressToJump = idaapi.get_imagebase() + InputOffsetInt
        if(idaapi.jumpto(AddressToJump)):
            print("[%s] 0x%X -> %X" % (PLUGIN_NAME, InputOffsetInt, AddressToJump))
        else:
            print("[%s] Failed to jump to address with offset 0x%X" % (PLUGIN_NAME, InputOffsetInt))

        return 1
    
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

#Other
def is_hex(s):
    try:
        int(s.lower(), 16)
        return True
    except ValueError:
        return False