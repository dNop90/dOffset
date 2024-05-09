function isHex(str)
    return str:match("^%x+$") ~= nil
end

function GetOffsetResult(Address, bWithModuleName)
    if((not Address) or (not inModule(Address))) then
        return nil
    end

    local ModuleName = getNameFromAddress(Address)
    if(isHex(ModuleName)) then
        return nil
    end

    if(bWithModuleName) then
        return ModuleName
    end

    local SubStrings = {}
    for text in string.gmatch(ModuleName, "[^+]+") do
        table.insert(SubStrings, text)
    end

    return SubStrings[2]
end

function dOffset_GetOffset(bDisassembler)
    local CurrentSelectedAddress = nil
    if(bDisassembler) then
        CurrentSelectedAddress = getMemoryViewForm().DisassemblerView.SelectedAddress
    else
        CurrentSelectedAddress = getMemoryViewForm().HexadecimalView.SelectionStart
    end
    
    local Offset = GetOffsetResult(CurrentSelectedAddress, false)
    if(not Offset) then
        showMessage("Unable to get offset")
        return
    end

    writeToClipboard(Offset)
end

function dOffset_GetModuleOffset(bDisassembler)
    local CurrentSelectedAddress = nil
    if(bDisassembler) then
        CurrentSelectedAddress = getMemoryViewForm().DisassemblerView.SelectedAddress
    else
        CurrentSelectedAddress = getMemoryViewForm().HexadecimalView.SelectionStart
    end

    local Offset = GetOffsetResult(CurrentSelectedAddress, true)
    if(not Offset) then
        showMessage("Unable to get offset")
        return
    end

    writeToClipboard(Offset)
end

function Add_dOffsetMenu(bDisassembler)
    local MainPopupMenu = nil
    if(bDisassembler) then
        MainPopupMenu = getMemoryViewForm().DisassemblerView.PopupMenu
    else
        MainPopupMenu = getMemoryViewForm().HexadecimalView.PopupMenu
    end

    -- Menu
    local dOffsetMenu_Main = createMenuItem(MainPopupMenu)
    dOffsetMenu_Main.Caption = 'dOffset'
    MainPopupMenu.Items.add(dOffsetMenu_Main)

    -- Sub menu
    local dOffsetMenu_GetOffset = createMenuItem(dOffsetMenu_Main)
    dOffsetMenu_GetOffset.Caption = 'Get offset'
    dOffsetMenu_GetOffset.OnClick = function(sender)
        dOffset_GetOffset(bDisassembler)
    end
    dOffsetMenu_Main.add(dOffsetMenu_GetOffset)

    local dOffsetMenu_GetModuleOffset = createMenuItem(dOffsetMenu_Main)
    dOffsetMenu_GetModuleOffset.Caption = 'Get module name + offset'
    dOffsetMenu_GetModuleOffset.OnClick = function(sender)
        dOffset_GetModuleOffset(bDisassembler)
    end
    dOffsetMenu_Main.add(dOffsetMenu_GetModuleOffset)
end

-- Add to CE
Add_dOffsetMenu(true)
Add_dOffsetMenu(false)