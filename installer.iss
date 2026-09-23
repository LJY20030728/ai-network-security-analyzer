; ============================================================
; AI网络安全智能分析系统 - Inno Setup 安装脚本
; 功能：
;   1. 标准安装向导（中文/英文），无需管理员权限（per-user 安装）
;   2. 自动检测系统是否缺少 WebView2 Runtime，缺失则弹窗提示并联网自动安装
;   3. 安装时可选填写大模型 API Key（写入 .env，不写死进程序）
;   4. 创建开始菜单/桌面快捷方式，安装完成后可立即启动
; 编译：ISCC.exe installer.iss
; ============================================================

[Setup]
AppId={{8A2B9C31-4E7D-4F3A-9C21-5D6E7F8A9B0C}
AppName=AI网络安全智能分析系统
AppVersion=3.1.1
AppVerName=AI网络安全智能分析系统 3.1.1
AppPublisher=AI Network Security Analyzer
DefaultDirName={autopf}\AI网络安全分析系统
DefaultGroupName=AI网络安全智能分析系统
DisableProgramGroupPage=no
DisableDirPage=no
PrivilegesRequired=lowest
OutputDir=installer_output
OutputBaseFilename=AI网络安全智能分析系统_Setup_3.1.1
Compression=lzma2/ultra
SolidCompression=yes
WizardStyle=modern
SetupIconFile=assets\app_icon.ico
UninstallDisplayIcon={app}\AI网络安全分析系统.exe
VersionInfoVersion=3.1.1
VersionInfoDescription=AI网络安全智能分析系统 安装程序
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "chinesesimplified"; MessagesFile: "installer\ChineseSimplified.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "dist\AI网络安全分析系统\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
; WebView2 微软官方在线安装器（仅安装时临时释放，不写入安装目录；约 2MB）
Source: "assets\MicrosoftEdgeWebView2Setup.exe"; Flags: dontcopy
; 注意：.env 不在打包产物中（API Key 绝不写死），由安装流程或应用内设置引导生成

[Icons]
Name: "{group}\AI网络安全智能分析系统"; Filename: "{app}\AI网络安全分析系统.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\AI网络安全智能分析系统"; Filename: "{app}\AI网络安全分析系统.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\AI网络安全分析系统.exe"; Description: "{cm:LaunchProgram,AI网络安全智能分析系统}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: files; Name: "{app}\.env"
Type: filesandordirs; Name: "{app}\data"

[Code]
var
  ApiKeyPage: TInputQueryWizardPage;

{ ============ WebView2 Runtime 检测 ============ }
function IsWebView2Installed: Boolean;
var
  Ver, RegPath: String;
begin
  Result := False;
  Ver := '';
  if IsWin64 then
    RegPath := 'SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
  else
    RegPath := 'SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}';

  if RegQueryStringValue(HKLM, RegPath, 'pv', Ver) then
    if (Ver <> '') and (Ver <> '0.0.0.0') then Result := True;

  if not Result then
  begin
    Ver := '';
    if RegQueryStringValue(HKCU, 'Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'pv', Ver) then
      if (Ver <> '') and (Ver <> '0.0.0.0') then Result := True;
  end;
end;

{ 安装程序启动最早期：若缺 WebView2，先明确告知将自动安装 }
function InitializeSetup: Boolean;
begin
  Result := True;
  if not IsWebView2Installed then
    MsgBox(
      '检测到系统尚未安装 Microsoft WebView2 Runtime —— 这是本程序界面运行所必需的组件。' #13#10 #13#10 +
      '点击「安装」后，安装程序会自动联网下载并静默安装该组件（内置约 2MB 的微软官方下载器，运行时从微软服务器下载，请保持网络畅通）。',
      mbInformation, MB_OK);
end;

{ 点击「安装」后、复制文件前：自动下载安装 WebView2；返回非空字符串则作为错误展示 }
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  SetupPath: String;
  Code: Integer;
begin
  Result := '';
  if IsWebView2Installed then exit;

  try
    WizardForm.StatusLabel.Caption := '正在下载并安装 WebView2 Runtime，首次需联网，请稍候 ...';
  except
  end;

  ExtractTemporaryFile('MicrosoftEdgeWebView2Setup.exe');
  SetupPath := ExpandConstant('{tmp}\MicrosoftEdgeWebView2Setup.exe');

  if not Exec(SetupPath, '/silent /install', '', SW_HIDE, ewWaitUntilTerminated, Code) then
  begin
    Result := '无法启动 WebView2 安装程序。请联网后重试，或手动从微软官网安装 WebView2 Runtime。';
    exit;
  end;

  { 0=成功; 3010=成功需重启; 1638=已存在更新版本 }
  if Code = 3010 then NeedsRestart := True;
  if (Code <> 0) and (Code <> 3010) and (Code <> 1638) then
  begin
    Result := 'WebView2 Runtime 自动安装失败（错误代码 ' + IntToStr(Code) + '）。请联网后重试，或手动从微软官网安装 WebView2 Runtime。';
    exit;
  end;

  if not IsWebView2Installed then
    Result := 'WebView2 Runtime 安装后仍未检测到。请检查网络后重试，或手动从微软官网安装 WebView2 Runtime。';
end;

{ ============ 安装向导：大模型 API 配置页（可选） ============ }
procedure InitializeWizard;
begin
  ApiKeyPage := CreateInputQueryPage(wpSelectTasks,
    '大模型 API 配置（可选）',
    '填写你的大模型 API Key，用于 AI 威胁研判与安全问答',
    '该配置将保存到安装目录下的 .env 文件，不会写入程序本体，可随时修改。' + #13#10 +
    '留空可跳过，核心检测（规则/监督模型/时序基线/孤立森林）无需 Key 即可运行。' + #13#10 + #13#10 +
    '常用服务商：' + #13#10 +
    '  智谱AI          https://open.bigmodel.cn/api/paas/v4   glm-4.5-air' + #13#10 +
    '  DeepSeek        https://api.deepseek.com              deepseek-chat' + #13#10 +
    '  通义千问        https://dashscope.aliyuncs.com/compatible-mode/v1   qwen-turbo' + #13#10 +
    '  Ollama 本地模型 http://localhost:11434/v1             qwen2.5:7b（Key 填任意值）');

  ApiKeyPage.Add('API Key：', True);
  ApiKeyPage.Add('API 地址 (Base URL)：', False);
  ApiKeyPage.Add('模型名称：', False);

  ApiKeyPage.Values[0] := '';
  ApiKeyPage.Values[1] := 'https://open.bigmodel.cn/api/paas/v4';
  ApiKeyPage.Values[2] := 'glm-4.5-air';
end;

{ 安装完成后写入 .env }
procedure CurStepChanged(CurStep: TSetupStep);
var
  EnvPath, Content, Key, BaseUrl, Model: String;
begin
  if CurStep = ssPostInstall then
  begin
    Key := Trim(ApiKeyPage.Values[0]);
    BaseUrl := Trim(ApiKeyPage.Values[1]);
    Model := Trim(ApiKeyPage.Values[2]);

    if BaseUrl = '' then
      BaseUrl := 'https://open.bigmodel.cn/api/paas/v4';
    if Model = '' then
      Model := 'glm-4.5-air';

    EnvPath := ExpandConstant('{app}\.env');

    if Key <> '' then
    begin
      Content := '# Generated by installer' + #13#10 +
                 'LLM_API_KEY=' + Key + #13#10 +
                 'LLM_BASE_URL=' + BaseUrl + #13#10 +
                 'LLM_MODEL=' + Model + #13#10;
    end
    else
    begin
      Content := '# API key not configured yet; configure in app Settings' + #13#10 +
                 'LLM_API_KEY=' + #13#10 +
                 'LLM_BASE_URL=' + BaseUrl + #13#10 +
                 'LLM_MODEL=' + Model + #13#10;
    end;

    SaveStringToFile(EnvPath, Content, False);
  end;
end;
