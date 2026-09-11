# DC3WY 中文本地化笔记
> 游戏详细：https://vndb.org/v17743
> | 工具 |说明 |
> |:---|:---|
> | [MesTextTool](https://github.com/cokkeijigen/MesTextTool) | Mes文本的提取导入 |
> |[sagilio::GARbro](https://github.com/sagilio/GARbro)| *.CRX图片类型封装转换|
> | [x32dbg](https://x64dbg.com/) | 静态动态调试分析 |
> | IDA 9 PRO | 静态逆向分析 |
> | CFF Explorer| 修改IAT |
## 0x00 去除DVD和KEY验证
首先是DVD验证，这可以直接搜索字符`DVD`串或者断`MessageBoxA`就能找到位置。可以发现上面有个跳转是调到下面弹出验证消息的逻辑，直接`nop`掉跳转即可
![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_00.png) 
其次是Key验证弹窗，这个可以搜字符串`InstKey`找到，可以看到有三个地方，不好判断具体是哪个<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_01.1.png)

所以直接上`x32dbg`，这里直接断`DialogBoxParamA`，此时找到`sub_40EA30`函数里调用了：
![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_01.png) 
可以发现这个函数有多个引用<br>
![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_02.png) 
所以还需要继续下断点查找是哪里调用了
![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_03.png) 
最终来到`0x425F80`这个地址，可以发现这个是一个循环一直调用着`sub_40EA30`，不难猜出通过验证的逻辑肯定是走`jmp dc3wy.429434`
![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_04.png) 
修改方法就是直接把`call <dc3wy.40EA30>`改成`jmp dc3wy.429434`，~~其余的nop就行了(强迫症)~~ 即可<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_05.png) <br>

## 0x01 一些系统API的HOOK
### CreateFileA与FindFirstFileA
为了实现与原版文件共存，因此需要Hook这两个函数，详细可以到官方文档查看：[FindFirstFileA](https://learn.microsoft.com/zh-cn/windows/win32/api/fileapi/nf-fileapi-findfirstfilea)，[CreateFileA](https://learn.microsoft.com/zh-cn/windows/win32/api/fileapi/nf-fileapi-createfilea)
```cpp
Patch::Hooker::Add<DC3WY::CreateFileA>(::CreateFileA);       // 添加Hook
Patch::Hooker::Add<DC3WY::FindFirstFileA>(::FindFirstFileA); // 添加Hook
```
这里声明一个辅助函数`ReplacePathA`用于查找并替换文件
```cpp
auto DC3WY::ReplacePathA(std::string_view path) -> std::string_view
{
    static std::string new_path{};
    size_t pos{ path.find_last_of("\\/") };
    if (pos != std::wstring_view::npos)
    {
        new_path = std::string{ ".\\cn_Data" }.append(path.substr(pos));
        DWORD attr { ::GetFileAttributesA(new_path.c_str()) };
        if (attr != INVALID_FILE_ATTRIBUTES)
        {
            return new_path;
        }
    }
    return {};
}

  static auto WINAPI CreateFileA(LPCSTR lpFN, DWORD dwDA, DWORD dwSM, LPSECURITY_ATTRIBUTES lpSA, DWORD dwCD, DWORD dwFAA, HANDLE hTF) -> HANDLE
  {
      std::string_view new_path{ DC3WY::ReplacePathA(lpFN) };
      return Patch::Hooker::Call<DC3WY::CreateFileA>(new_path.empty() ? lpFN : new_path.data(), dwDA, dwSM, lpSA, dwCD, dwFAA, hTF);
  }

  static auto WINAPI FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData) -> HANDLE
  {
      std::string_view new_path{ DC3WY::ReplacePathA(lpFileName) };
      return Patch::Hooker::Call<DC3WY::FindFirstFileA>(new_path.empty() ? lpFileName : new_path.data(), lpFindFileData);
  }
```
---
### GetGlyphOutlineA
这个主要是用来更改游戏字体与文本编码
```cpp
Patch::Hooker::Add<DC3WY::GetGlyphOutlineA>(::GetGlyphOutlineA); // 添加Hook
```
```cpp
static auto WINAPI GetGlyphOutlineA(HDC hdc, UINT uChar, UINT fuf, LPGLYPHMETRICS lpgm, DWORD cjbf, LPVOID pvbf, MAT2* lpmat) -> DWORD
{
    /* 此处暂时省略，后面会与FontManager一起详细讲解 */ 
    return Patch::Hooker::Call<DC3WY::GetGlyphOutlineA>(hdc, uChar, fuf, lpgm, cjbf, pvbf, lpmat);
}
```
---
### SendMessageA
这是一个给窗口发送消息的函数，详细可以到官方文档查看：[SendMessageA](https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-sendmessagea) <br>那为什么要Hook它呢？那当然是为了更改这个对话框的文本内容。
![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_06.png) <br>

这个可以搜索字符串`データVer`定位到`sub_40DA40`这个函数
![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_07.png) 

通过`ida`反编译可以一目了然，这个`SendMessageA(DlgItem, 0xCu, 0x104u, lParam);`就是在更改对话框文本内容了。
```cpp
Patch::Hooker::Add<DC3WY::SendMessageA>(::SendMessageA); // 添加Hook
```
```cpp
static constexpr inline wchar_t PatchDesc[]
{
    L"本补丁由【COKEZIGE STUDIO】制作并免费发布\n\n"
    L"仅供学习交流使用，禁止一切直播录播和商用行为\n\n"
    L"补丁源代码已开源至GitHub\n\n"
    L"https://github.com/cokkeijigen/dc3_cn"
};

static auto WINAPI SendMessageA(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) -> LRESULT
{
    // 为了确保此条消息是更改对话框文本的，还需要判断wParam和DlgCtrlID
    if (uMsg == 0xCu && wParam == 0x104u)
    {
        auto ctr_id{ ::GetDlgCtrlID(hWnd) };
        if (ctr_id == 1005)
        {
            auto result
            {
                ::SendMessageW
                (
                    { hWnd }, { 0x0000000Cu },
                    { sizeof(DC3WY::PatchDesc) / sizeof(wchar_t) },
                    { reinterpret_cast<LPARAM>(DC3WY::PatchDesc) }
                )
            };
            return { result };
        }
    }
    return Patch::Hooker::Call<DC3WY::SendMessageA>(hWnd, uMsg, wParam, lParam);
}
```

至于这个`バージョン情報`的字符串如何更改，可以看后面的“**其他文本修改**”中有讲到。

![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_06.1.png)

当然也可以直接去Hook `sub_40DA40`这个函数来实现修改，我这里偷个懒直接Hook `SendMessageA`了。

## 0x02 一些游戏函数的HOOK

### DC3WY::WndProc <0x40FC20>
为什么要Hook这个函数？这个函数是游戏窗口过程函数，在我们需要拿到游戏窗口句柄或者在创建窗口时做一些初始化操作，那么Hook游戏的`WndProc`是最好的选择。

这个函数很好找，直接去查找`RegisterClassA`的引用，详细可以到官方文档查看：[RegisterClassA](https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-registerclassa)
![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_08.png) <br>

依旧是通过`ida`反编译查看，这个`WndClass.lpfnWndProc = sub_40FC20;` 就是`DC3WY::WndProc`了
```cpp
Patch::Hooker::Add<DC3WY::WndProc>(reinterpret_cast<void*>(0x40FC20)); // 添加Hook
```
```cpp
static constexpr inline wchar_t TitleName[]
{
    L"【COKEZIGE STUDIO】Da Capo Ⅲ With You - CHS Ver.1.00"
    L" ※仅供学习交流使用，禁止一切直播录播和商用行为※" 
};
```
```cpp
auto CALLBACK DC3WY::WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) -> LRESULT
{
    if (uMsg == WM_CREATE) 
    {
        // 设置窗口标题
        ::SetWindowTextW(hWnd, DC3WY::TitleName);
        /* 一些初始化操作，此处省略…… */
    }
    else
    {
        /* 其他逻辑…… */
    }
    return Patch::Hooker::Call<DC3WY::WndProc>(hWnd, uMsg, wParam, lParam);
}
```

**初始化`Utils::FontManager`**，这是我自己写的一个字体选择器GUI，具体实现大家自行查看源码：[utillibs/fontmanager](https://github.com/cokkeijigen/circus_engine_patchs/tree/master/CircusEnginePatchs/utillibs/fontmanager)。

```cpp

Utils::FontManager DC3WY::FontManager{};

auto CALLBACK DC3WY::WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) -> LRESULT
{
    if (uMsg == WM_CREATE) 
    {
        // 设置窗口标题
        ::SetWindowTextW(hWnd, DC3WY::TitleName);

        HMENU SystemMenu{ ::GetSystemMenu(hWnd, FALSE) };
        if (SystemMenu != nullptr)
        {
            // 向系统菜单添加 “更改字体” 选项，标识为0x114514
            ::AppendMenuW(SystemMenu, MF_UNCHECKED, 0x114514, L"更改字体");
        }
        if (!DC3WY::FontManager.IsInit())
        {
            DC3WY::FontManager.Init(hWnd);
        }

    }
    else if (uMsg == WM_SYSCOMMAND)
    {
        if (wParam == 0x114514)
        {
            if (DC3WY::FontManager.GUI() != nullptr)
            {
                // 显示选择字体窗口
                DC3WY::FontManager.GUIChooseFont();
            }
            return TRUE;
        }
    }
    else if (uMsg == WM_SIZE)
    {
        // 当窗口大小改变时需要更新一下显示的状态，针对全屏与窗口模式切换
        if (DC3WY::FontManager.GUI() != nullptr)
        {
            DC3WY::FontManager.GUIUpdateDisplayState();
        }
    }
    else
    {
        /* 其他逻辑…… */
    }
    return Patch::Hooker::Call<DC3WY::WndProc>(hWnd, uMsg, wParam, lParam);
}
```
![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_09.png)

那么如何引用到游戏中呢？很简单，就是在`GetGlyphOutlineA`中设置就行了，这就是我为什么需要Hook它。

在`GetGlyphOutlineA`中可以通过`FontManager::GetJISFont`和`FontManager::GetGBKFont`来获取当前选择字体的`HFONT`对象。
但是这两个函数都是需要一个`size`作为参数的，那么从哪获取呢？答案很简单，直接从第一个参数`HDC hdc`中获取即可。

使用`GetTextMetricsA`([详细](https://learn.microsoft.com/windows/win32/api/wingdi/nf-wingdi-gettextmetrics))获取当前字体的`TEXTMETRIC`，
这个`TEXTMETRIC`。

```cpp
  tagTEXTMETRICA lptm{};
  ::GetTextMetricsA(hdc, &lptm);
  auto size{ lptm.tmHeight }; // 这个就可以作为size使用
  HFONT font{ DC3WY::FontManager.GetGBKFont(size) };
```

获取到`HFONT`对象后再通过`SelectObject`([详细](https://learn.microsoft.com/zh-cn/windows/win32/api/wingdi/nf-wingdi-SelectObject))来设置`hdc`的新字体。<br>
※ 注意：用完需要再调用`SelectObject`还原回去。为什么要还原回去呢？因为这个游戏使用了多种大小的字体，而`FontManager`会将字体大小作为`key`将`HFONT`存到`map`中，当通过`FontManagerGUI`更改字体大小时，会把这个`map`中的所有字体通过原始大小进行计算，获得缩放比例再更新并创建出与其大小相对新的`HFONT`对象(详细：[Utils::FontManager::m_GUI::OnChanged](https://github.com/cokkeijigen/circus_engine_patchs/blob/master/CircusEnginePatchs/utillibs/fontmanager/FontManager.cpp#L24)、[Utils::FontManagerGUI::MakeFont](https://github.com/cokkeijigen/circus_engine_patchs/blob/master/CircusEnginePatchs/utillibs/fontmanager/FontManagerGUI.cpp#L711))，如果不还原，下次就无法通过大小确定是哪个字体了。

```cpp
  static auto WINAPI GetGlyphOutlineA(HDC hdc, UINT uChar, UINT fuf, LPGLYPHMETRICS lpgm, DWORD cjbf, LPVOID pvbf, MAT2* lpmat) -> DWORD
  {
      if (tagTEXTMETRICA lptm{}; ::GetTextMetricsA(hdc, &lptm))
      {
          HFONT font{ DC3WY::FontManager.GetGBKFont(lptm.tmHeight) };
          if (font != nullptr)
          {
              font = { reinterpret_cast<HFONT>(::SelectObject(hdc, font)) };
              DWORD result{ Patch::Hooker::Call<DC3WY::GetGlyphOutlineA>(hdc, uChar, fuf, lpgm, cjbf, pvbf, lpmat) };
              static_cast<void>(::SelectObject(hdc, font));
              return result;
          }
      }
      return Patch::Hooker::Call<DC3WY::GetGlyphOutlineA>(hdc, uChar, fuf, lpgm, cjbf, pvbf, lpmat);
  }
```

音符`♪`符号与其他特殊符号的支持这个实现也很简单，只需要将`♪`换成一个GBK编码里存在的字符，例如`§`，然后再在`GetGlyphOutlineA`里替换即可。注意这里使用的是`FontManager::GetJISFont`，其他要替换其他在特殊符号也同理，不多说了。
```cpp
if (0xA1EC == uChar) // § -> ♪
{
    HFONT font{ DC3WY::FontManager.GetJISFont(lptm.tmHeight) };
    if (font != nullptr)
    {
        font = { reinterpret_cast<HFONT>(::SelectObject(hdc, font)) };
        DWORD result{ ::GetGlyphOutlineW(hdc, L'♪', fuf, lpgm, cjbf, pvbf, lpmat) };
        static_cast<void>(::SelectObject(hdc, font));
        return result;
    }
}
```

**初始化`XSub::GDI::ImageSubPlayer`。** 这也是我自己写的一个字幕播放器，目前还是个临时方案 ~~（等我把libass整明白了再继续完善）~~ ，具体实现大家自行查看源码：[dc3wy/sub](https://github.com/cokkeijigen/circus_engine_patchs/tree/master/CircusEnginePatchs/dc3wy/sub)、[utillibs/xsub](https://github.com/cokkeijigen/circus_engine_patchs/tree/master/CircusEnginePatchs/utillibs/xsub)。

```cpp
XSub::GDI::ImageSubPlayer* SubPlayer{};

auto CALLBACK DC3WY::WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) -> LRESULT
{
    if (uMsg == WM_CREATE) 
    {
        /* 此处省略…… */
        if (DC3WY::SubPlayer == nullptr)
        {
            // 使用new来创建XSub::GDI::ImageSubPlayer实例
            DC3WY::SubPlayer =
            {
                new XSub::GDI::ImageSubPlayer{ hWnd }
            };

            // 设置一个默认字幕位置
            DC3WY::SubPlayer->SetDefualtPoint
            (
                XSub::Point
                {
                    .align{ XSub::Align::Center },
                }
            );
        }
    }
    else if (uMsg == WM_MOVE)
    {
        if (DC3WY::SubPlayer != nullptr)
        {
            // 游戏窗口移动时要更新字幕窗口的位置
            auto x{ static_cast<int>(LOWORD(lParam)) };
            auto y{ static_cast<int>(HIWORD(lParam)) };
            DC3WY::SubPlayer->SetPosition(x, y, true);
        }
    }
    else if(uMsg == WM_SIZE)
    {
        if (DC3WY::SubPlayer != nullptr)
        {
            if (wParam == SIZE_MINIMIZED)
            {
                // 当窗口最小化时隐藏
                DC3WY::SubPlayer->Hide();
                DC3WY::SubPlayer->UpdateLayer();
            }
            else if (wParam == SIZE_RESTORED || wParam == SIZE_MAXIMIZED)
            {
                DC3WY::SubPlayer->Show();
                // 窗口显示或者改变大小时要重新同步
                DC3WY::SubPlayer->SyncToParentWindow(true);
            }
        }
    }
    else
    {
        /* 其他逻辑…… */
    }
    return Patch::Hooker::Call<DC3WY::WndProc>(hWnd, uMsg, wParam, lParam);
}
```

我这里声明一个辅助函数来加载和播放字幕

```cpp
static auto LoadXSubAndPlayIfExist(std::string_view file, bool play) -> bool
{
    if (DC3WY::SubPlayer == nullptr)
    {
        return { false };
    }

    std::string path{ ".\\cn_Data\\" };

    auto pos{ file.rfind("\\") };
    if (pos != std::string_view::npos)
    {
        path.append(file.substr(pos + 1)).append(".xsub");
    }
    else
    {
        path.append(file).append(".xsub");
    }

    bool is_load { DC3WY::SubPlayer->Load(path) };
    if (is_load)
    {
        if (play) { DC3WY::SubPlayer->Play(); }
    }
    return { is_load };
}
```
---
### DC3WY::ComPlayVideo<0x444920>、DC3WY::ComStopVideo<0x444640> （这里函数名自己取的）

这两个是控制OP视频的播放暂停的函数，当然Hook它们当然自不必说，因为需要一个字幕加载和播放的时机，而控制游戏的视频播放停止函数就是最好的选择。这个游戏使用COM接口来播放视频，直接查找`CoCreateInstance`（[详细](https://learn.microsoft.com/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance)）的引用也能找到，但是太多了，直接上调试器，找到这两个函数有两种方法可以快速定位。
首先是经典的土方法，直接断文件相关的API看看他是在哪读取的，我这里先试过了`CreateFileA`，不过它并没有使用这个，而是`CreateFileW`，但游戏exe并没有导入这个函数，所以需要从`kernel32.dll`中下断点。<br>
![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_10.png)

运行直到发现路径是OP视频的为止，然后直接取消断点，然后按下`Alt+F9`运行到用户代码，可以看到上面有个`CoCreateInstance`，这里就是我们要找的函数了。<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_11.png)

然后就是第二种方法，那就是直接断`CoCreateInstance`，这个函数普通断点可能停不下来，建议使用设置硬件断点（执行）。<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_12.png)

这里停下来之后，然后取消断点，接着在堆栈窗口选中顶部的地址按下回车就能来到我们要找的函数了。效果都一样，只不过断`CoCreateInstance`的前提是你得知道它用了这个，不然就只能靠断文件相关的API这种土方法找了。

![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_13.png)

这个`sub_444680`就是这游戏用来创建COM实例并播放视频的函数了，这里都是调用着COM接口的虚函数，看不懂没关系，因为我们只需要找一个播放字幕时机的函数，不过我这里没有选择Hook这个函数，这个函数就只有一个调用地方，我选择Hook调用它的上层函数，也就是这个`sub_444920`。<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_14.png)

简单看一下这个`sub_444920`，<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_15.png)

这个`String1`应该就是文件路径了，`ida`点进去可以看到地址是`0x4E65F8`，通过计算尾部到头部的地址长度，可以得出它的大小为260，`也就是`MAX_PATH`。<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_16.png)

这里先简单对它进行一个Hook

```cpp
Patch::Hooker::Add<DC3WY::ComPlayVideo_Hook>(reinterpret_cast<void*>(0x444920)); // 添加Hook
```

```cpp
auto DC3WY::ComPlayVideo_Hook(void) -> int32_t
{
    std::string_view movie_file_path{ reinterpret_cast<const char*>(0x4E65F8) };
    auto result{ Patch::Hooker::Call<DC3WY::ComPlayVideo_Hook>() };
    return { result };
}
```

现在播放函数有了，那还差个暂停视频的函数，既然是通过`CoCreateInstance`创建的实例，那么我们可以直接查找其他使用这个实例的地方。<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_17.png)

很幸运的是它的引用并不多，来到`sub_4443B0`可以看到，这个`ppv`被重新赋值为`0`，那么就可以大胆猜测这个函数应该是和视频停止播放相关<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_18.png)

不太确定的，我们可以往上查找追踪，看看在哪调用了这个函数。可以看到只有一个<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_19.png)

来看看这个`sub_444640`，可以发现它在调用`sub_4443B0`之后又将`String1`（也就是上面讲到的文件路径）赋值为`0`，这下基本确定，这个函数是和结束播放视频相关的了<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_20.png)

我这里就选择Hook `sub_444640`了

```cpp
Patch::Hooker::Add<DC3WY::ComStopVideo_Hook>(reinterpret_cast<void*>(0x444640)); // 添加Hook
```

```cpp
auto DC3WY::ComStopVideo_Hook(void) -> int32_t
{
    auto result{ Patch::Hooker::Call<DC3WY::ComStopVideo_Hook>() };
    return { result };
}
```

这下视频的播放暂停函数都有了，接着来写加载外挂字幕并和视频一起播放

```cpp
static bool IsOpMoviePlaying{}; // 记录是否正在播放OP

auto DC3WY::ComPlayVideo_Hook(void) -> int32_t
{
    std::string_view movie_file_path{ reinterpret_cast<const char*>(0x4E65F8) };
    if (!movie_file_path.empty())
    {
        auto pos{ movie_file_path.rfind("\\") };
        if (pos != std::string_view::npos)
        {
            // 这里来截取文件名
            auto name{ movie_file_path.substr(pos + 1) };
            if (name.size() >= 7)
            {
                // 由于文件名并不长，所以我直接使用硬编码的方式来对比文件名
                auto is_gop_mpg
                {
                    (name[0] == 'g' || name[0] == 'G') &&
                    (name[1] == 'o' || name[1] == 'O') &&
                    (name[2] == 'p' || name[2] == 'P') &&
                    (name[3] == '.') &&
                    (name[4] == 'm' || name[4] == 'M') &&
                    (name[5] == 'p' || name[5] == 'P') &&
                    (name[6] == 'g' || name[6] == 'G')
                };
                if (is_gop_mpg) // gop.mpg
                {
                    // 这个274是这个op视频对应的字幕文件，false表示只加载不播放
                    DC3WY::LoadXSubAndPlayIfExist("274", false);
                }
            }
        }
    }
    
    // 调用原来的函数
    auto result{ Patch::Hooker::Call<DC3WY::ComPlayVideo_Hook>() };
    
    DC3WY::IsOpMoviePlaying = { result >= 0 };
    if (DC3WY::IsOpMoviePlaying)
    {
        if (DC3WY::SubPlayer != nullptr)
        {
            auto is_load{ DC3WY::SubPlayer->IsLoad() };
            if (is_load)
            {
                DC3WY::SubPlayer->UseDefualtAlign(true);
                DC3WY::SubPlayer->UseDefualtHorizontal();
                DC3WY::SubPlayer->Play();
            };
        }

        if (DC3WY::FontManager.GUI() != nullptr)
        {
            // 由于这个游戏播放视频会阻塞消息循环
            // 所以我这里需要隐藏（如果显示的话）FontManager避免造成卡死的BUG
            DC3WY::FontManager.GUI()->HideWindow();
        }
    }
 
    return { result };
}
```

```cpp
auto DC3WY::ComStopVideo_Hook(void) -> int32_t
{
    if (DC3WY::SubPlayer != nullptr)
    {
        // 停止字幕播放
        DC3WY::SubPlayer->Stop();
        // 取消加载
        DC3WY::SubPlayer->UnLoad();
        // 恢复不使用默认字幕位置
        DC3WY::SubPlayer->UnuseDefualtPoint();
    }
    DC3WY::IsOpMoviePlaying = { false };
    auto result{ Patch::Hooker::Call<DC3WY::ComStopVideo_Hook>() };
    return { result };
}
```

![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_21.png)
---
### DC3WY::AudioStop<0x432490>，DC3WY::AudioPlay<0x432490>（这里函数名自己取的）

游戏的ED是使用了播放音频+滚动图片的方式呈现，要加字幕只能是去hook游戏播放音频相关的函数。它使用了`DirectSound`来播放音频，所以我们可以通过去给`DirectSound`的播放和停止接口函数下个断点，就能找到游戏的播放暂停函数了。<br>

首先我们先来到`x32dbg`的符号窗口，找到`dsound.dll`，然后右键`下载此模块的符号信息`<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_22.png)

接着使用正则表达式`Play[\s\S]+DirectSoundBuffer`过滤出播放函数，可以发现一共有三个，不确定具体是调用了哪个，所以这里全都都下断点。<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_23.png)

停下来之后，就可以取消断点了，接着在堆栈窗口选中顶部的地址按下回车回到调用处<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_24.png)

这里就是我们要找的播放函数了<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_25.png)

来到`ida`反编译，简单观察，`dword_4A95EC`应该是个存放多个`DirectSoundBuffer`的数组，`a2`就很明显了是个`index`，`a1`不明，暂且当做是一个`flag`吧<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_26.png)

在Hook之前我们还得需要得到当前播放的文件名字，幸运的是我在查看` sub_431870`被调用时的堆栈，正好在`esp+0x12C`发现了。<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_27.png)
```cpp
Patch::Mem::JmpWrite(0x431870, DC3WY::JmpAudioPlayHook); // 函数逻辑不复杂，我这里手写不调用原函数，因此使用JmpWrite添加Hook
```
因为要拿到文件名，所以这里需要手写内联汇编
```cpp
__declspec(naked) auto DC3WY::JmpAudioPlayHook(void) -> void
 {
    __asm
    {
        sub esp, 0x04	                  // 需要使用栈来将文件名参数传递，所以这里esp+0x04
        mov eax, dword ptr ss:[esp+0x04]  // 这里交换call的返回地址
        mov dword ptr ss:[esp], eax
        mov eax, dword ptr ss:[esp+0x130] // 因为上面esp+0x04了，所以文件名的地址变成了 0x12C+0x04 -> 0x130
        mov dword ptr ss:[esp+0x04], eax  // 根据传参顺序，最后一个入栈对应参数一
        jmp DC3WY::AudioPlay_Hook
    }
 }
```
代码基本照抄`ida`反编译的内容，在播放之后在插入一个我们自己播放字幕播放代码即可
```cpp
#include <dsound.h> // 为了方便使用DirectSound的API

static IDirectSoundBuffer* CurrentPlayingBuffer{}; // 需要记录当前播放字幕的音频Buffer

static auto __stdcall AudioPlay_Hook(const char* file, uint32_t flag, uint32_t index) -> int
{
    auto UnknownPtr{ reinterpret_cast<uintptr_t*>(0x4A95A4) };
    auto DirectSoundBuffers{ reinterpret_cast<IDirectSoundBuffer**>(0x4A95EC) };
    
    if (index == 0x01)
    {
        *reinterpret_cast<uint32_t*>(*UnknownPtr + 0x136C) = flag;
    }
    
    auto buffer{ DirectSoundBuffers[index] };
    if (buffer != nullptr)
    {
        // 播放音频
        auto result{ buffer->Play(0x00, 0x00, flag != 0x00) };

        // 如果当前的音频Buffer等于nullptr，则代表现在无字幕播放
        if (DC3WY::CurrentPlayingBuffer == nullptr)
        {
            // 加载音频文件对应的字幕，true代表加载完后立即播放
            auto is_load{ DC3WY::LoadXSubAndPlayIfExist(file, true) };
            if (is_load)
            {
                DC3WY::CurrentPlayingBuffer = { buffer };
            }
        }
        return { result };
    }
    return { NULL };
}
```

接着就是找到暂停播放的函数了，还是来到`dsound.dll`符号这边，使用正则表达式`Stop[\s\S]+DirectSoundBuffer`过滤出暂停函数，也是三个，不确定具体是哪个，所以一样全都都下断点。<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_28.png)

停下来之后，就可以取消断点了，接着在堆栈窗口选中顶部的地址按下回车回到调用处<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_29.png)

这里就是我们要找的暂停函数了<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_30.png)

依旧看看`ida`的反编译<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_31.png)

其中有个`(*(*result + 0x34))(result, 0);`不知道是什么，所以还是得来到`x32dbg`看看<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_32.png)

嗯，这下知道了，这个是`DirectSoundBuffer::SetCurrentPosition`，另外我顺便也进去看了一下`sub_432000`，里面有调用`DirectSoundBuffer::Release`，那这很明显了，这个函数是用来做销毁清理（释放内存）的。<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_33.png)

好，现在开始写Hook代码，主要逻辑也是基本照搬`ida`反编译内容，然后中间再插入停止字幕播放的代码即可。

```cpp
Patch::Mem::JmpWrite(0x432490, DC3WY::AudioStop_Hook); // 同上
```

```cpp
static IDirectSoundBuffer* CurrentPlayingBuffer{}; // 在AudioPlay_Hook中成功加载并播放字幕时会存放当前播放的Buffer

// 注意，原函数是__thiscall，这里使用__fastcall来替代，第一个参数两者相同都是ECX
// 而__fastcall第二个参数是EDX，__thiscall不用，所以要有个占位
static auto __fastcall AudioRelease(int32_t* m_this, int32_t, uint32_t index) -> DWORD
{
    auto RawCall{ reinterpret_cast<decltype(DC3WY::AudioRelease)*>(0x432000) };
    return RawCall(m_this, NULL, index);
}

// 同上
auto __fastcall DC3WY::AudioStop_Hook(int32_t* m_this, int32_t, uint32_t index) -> DWORD
{
    auto UnknownPtr{ reinterpret_cast<uintptr_t*>(0x4A95A4) };
    auto DirectSoundBuffers{ reinterpret_cast<IDirectSoundBuffer**>(0x4A95EC) };

    m_this[0x05 * index + 0x15] = 0x00;
    if (index - 0x01 <= 0x03 && *UnknownPtr != NULL)
    {
        auto uint8_ptr{ reinterpret_cast<uint8_t*>(*UnknownPtr) };
        *(uint8_ptr + (0x20 * index) + 0x4D10) = 0x00;
    }
    
    auto buffer{ DirectSoundBuffers[index] };
    if (buffer != nullptr)
    {
        auto is_current_playing_buffer
        {
            DC3WY::CurrentPlayingBuffer != nullptr &&
            buffer == DC3WY::CurrentPlayingBuffer
        };
        if (is_current_playing_buffer)
        {
            DC3WY::SubPlayer->Stop();
            DC3WY::SubPlayer->UnLoad();
            DC3WY::CurrentPlayingBuffer = { nullptr };
        }
        
        buffer->SetCurrentPosition(0x00);
        buffer->Stop();
        auto result{ DC3WY::AudioRelease(m_this, NULL, index) };
        return { result };
    }
    return { NULL };
}
```

![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_34.png)当然，音乐鉴赏模式下也能使用<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_35.png)

※补充，在播放OP视频时禁用字体选择

```cpp
static bool IsOpMoviePlaying{};

auto CALLBACK DC3WY::WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) -> LRESULT
{
    /* 这里省略了其他逻辑…… */
    if (uMsg == WM_SYSCOMMAND)
    {
        /* 这里省略了其他逻辑…… */
        if (wParam == 0x114514)
        {
            if (DC3WY::FontManager.GUI() != nullptr)
            {
                if (DC3WY::IsOpMoviePlaying)
                {
                    // 前面也说了由于这个游戏播放视频会阻塞消息循环
                    // 如果OP视频正在播放中就弹出这个弹窗
                    ::MessageBoxW
                    (
                        { hWnd },
                        { L"当前无法更改字体！" },
                        { L"WARNING" },
                        { MB_OK }
                    );
                    return FALSE;
                }
                DC3WY::FontManager.GUIChooseFont();
            }
            return TRUE;
        }
        /* 这里省略了其他逻辑…… */
    }
    /* 这里省略了其他逻辑…… */
    return Patch::Hooker::Call<DC3WY::WndProc>(hWnd, uMsg, wParam, lParam);
}
```

## 0x03 其他修改

### Backlog头像修复
可以看到，在汉化之后Backlog的角色头像全部丢失，这是因为汉化后的文本和原来日文的对不上，所以无法设置对应的图标，这时候我们只需要把程序用来判断的角色名也给改成中文的就行了。<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_36.png)

来到内存布局这边，选中所有段，然后`Ctrl+B`打开`搜索匹配特征`窗口，在`代码页`选择`Shift_JIS`输入角色名，例如`リッカ`，<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_37.png)

这里得到多个搜索结果，顺便点一个进去看看是不是我们想要的<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_38.png)

来到内存窗口，可以使用快捷键`Ctrl+R`来查找引用，我这里就查到了`0x4046B7`地址`push dc3wy.479668`引用了这个字符串<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_39.png)

接着到`ida`里看看……。嗯，都是角色名没错，基本可以确定这里<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_40.png)

再通过观察游戏图片，不难看出，这个`v28`和`v12`分别代表这头像所在行列，这里的逻辑是判断角色名并设置对应头像的行列<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_41.png)

我们只要将这些名字都换成中文就好，回到`x32dbg`在内存窗口选中数据，按下`Ctrl + E`就能直接编辑了，一般日文角色名的翻译都不会超过原文，所以这里可以放心直接在原地更改，记得勾选`保持大小`，`x32dbg`会自动给填充`00`。<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_42.png)

因为更改后的字符串比原文小，所以还需要接着更改`strlen`对比的长度<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_43.png)

值得注意的是，它这个`v12`是`edi`，而有些地方不是直接`mov`立即数，而是像这里一样`lea edi, ds:[eax-0x07]`，这里的`eax`是`strlen`的结果，`シャルル`的`strlen`是`8`，所以然后减去`7`得到`1`，改成翻译后的`夏露露`长度变成了`6`，因此为了保证改过后的结果也是`1`，要改成`lea edi, ds:[eax-0x05]`即可，其余的也一样，照猫画虎即可。<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_44.png)

![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_45.png)

最终效果：<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_46.png)

如果翻译后的字符串比原文长怎么办？那也有办法，那就是万能的Hook！我这里直接就从这个`else`这里开始Hook。<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_47.png)

对应地址为`0x404BFE`<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_48.png)

```cpp
Patch::Mem::JmpWrite(0x404BFE, DC3WY::JmpSetNameIconEx); // 添加Hook
```

```cpp
__declspec(naked) auto DC3WY::JmpSetNameIconEx(void) -> void
{
    mov dl, byte ptr ds:[0x004795BA]  // 搬运原地址的指令，长度为0x06
    mov eax, 0x00404C04               // 跳转回去原来的地址，0x404BFE + 0x06 -> 0x00404C04
    jmp eax
}
```

手写汇编不适合写一些复杂的逻辑，这里另外声明一个函数来实现

```cpp
static auto __stdcall SetNameIconEx(const char* name, int& line, int& row) -> BOOL
{
    return { static_cast<BOOL>(false) };
}
```

已知`v12`是`edi`，`v28`是`esp+0x10`，`v38`是`esp+0x3C`。这些都是可以通过`ida`查看，鼠标光标点击变量名，按下`tab`就能转到对应的汇编指令处。

```cpp
__declspec(naked) auto DC3WY::JmpSetNameIconEx(void) -> void
{
    __asm 
    {
        sub esp, 0x08                     // 需要两个int分别存储line和row，所以esp-0x08
        mov dword ptr ss:[esp], 0x00      // int row  = 0x00;
        mov dword ptr ss:[esp+0x04], 0x00 // int line = 0x00;
        
        lea eax, dword ptr ss:[esp]       
        push eax                          // push &row
        
        lea eax, dword ptr ss:[esp+0x4C] 
        push eax                          // push &line
        
        lea eax, dword ptr ss:[esp+0x4C]  // 前面esp-0x08 加上 push &row和&line，所以`v38(角色名字)`的地址
        push eax                          // 变成了 esp + (0x3C + 8 * 2) = esp + 0x4C
    
        call DC3WY::SetNameIconEx         // auto result = DC3WY::SetNameIconEx(name, &line, &row)
        test eax, eax
        jnz _succeed                      // if(result) goto _succeed

        add esp, 0x08                     // 恢复堆栈
        mov dl, byte ptr ds:[0x004795BA]  // 搬运原地址的指令，长度为0x06
        mov eax, 0x00404C04               // 跳转回去原来的地址，0x404BFE + 0x06 -> 0x00404C04
        jmp eax
    }
_succeed:
    __asm
    {
        mov edi, dword ptr ss:[esp]       // 把row的结果放到`v12`
        mov eax, dword ptr ss:[esp+4]     // 先将line的值放到eax
        add esp, 0x08                     // 恢复堆栈
        mov dword ptr ss:[esp+0x10], eax  // 把eax值放到`v28`
        mov eax, 0x00404D2E               // 跳转回去原来的地址
        jmp eax
    }
}
```

接着来到`DC3WY::SetNameIconEx`，现在就能随便对比超长角色名并设置图标了
```cpp
static auto __stdcall SetNameIconEx(const char* name, int& line, int& row) -> BOOL
{
     std::string_view _name{ name };
     if (_name.size() != 0) 
     {
         // 为了演示，我这里给其他名字设置了默认图标
         line = 3;
         row  = 4;
         return { static_cast<BOOL>(true) };
     }
    return { static_cast<BOOL>(false) };
}
```

![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_49.png)

![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_50.png)
---
### 文本注解修复

![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_51.png)

这是因为游戏判断使用的是`JIS`编码的`｛／｝`，而汉化后的文本是`GBK`导致对不上，要修复有两种方法。

第一种简单粗暴，那就是强行使用`JIS`编码在`GKB`中的字符：`｛`->`乷`、`／`->`乛`、`｝`->`乸`，替换上去即可。

![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_52.png)

第二种，到`exe`中更改，那么要怎么找到具体位置呢？`｛`编码`0x81 0x6F`、`／`编码为`0x81 0x5E`、`｝`编码为`0x81 0x70`，然后直接使用`搜索匹配特征`<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_53.png)

可能会有多个结果，这时候可以下个`硬件断点->读取`或者`Ctrl + R`查找引用，不太确定可以到`ida`看看反编译的代码<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_54.png)![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_55.png)
依次改成`GBK`编码即可，`｛`编码`0xA3 0xFB`、`／`编码为`0xA3 0xAF`、`｝`编码为`0xA3 0xFD`。（对了，这个引擎旧版是单独判字符每个字节，直接搜索常数过滤`cmp`就能找到)

---

### 其他文本修改

游戏内还是存在一些文本需要修改，其实完全可以使用`搜索匹配特征`来搜索定位，前面也有讲到了，相信看到这里，聪明的你们已经学会了如何照猫画虎。

![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_56.png)![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_57.png)

![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_58.png)如果有找不到的，可以尝试更换编码试试，例如`Unicode`、`UTF-8`等。像是这个窗口标题它就是`Unicode`字符串<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_59.png)

要注意的是，这里的数据是有结构的，译文比原文短可以使用`空格（0x20 0x00）`来填充<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_60.png)
但如果比原文长的话，也不是没有办法，通过Hook拿到窗口句柄，然后手动调用`SetWindowTextW`也能做到替换效果。

---

补充：游戏里有张表是存放存档标题名<br>![Image_text](https://raw.githubusercontent.com/cokkeijigen/circus_engine_patchs/master/Pictures/img_dc3wy_note_61.png)
这个直接在`x32dbg`里改有点麻烦了，最主要的是突然翻译有改动那就更麻烦了，所以我们直接把表复制出来，到自己代码中翻译好再写回去即可，后面改起来也方便。

```cpp
static inline const char* ChapterTitles[][2]
{
    { "WY_9_0610_E1_COM", "新考验？" },
    { "WY_9_0609_F25_AOI", "医生扮演" },
    { "WY_9_0609_F24_SRA", "贫乳才是世界的真理" },
    { "WY_9_0609_F23_SRR", "紧缚play" },
    // 此处省略…………
}
```

```cpp
Patch::Mem::MemWrite(0x49DF58, DC3WY::ChapterTitles, sizeof(DC3WY::ChapterTitles));
```

遇到类似这种连续的字符串表，都能使用这种方法。

总之笔记差不多就记到这里了，最后特别鸣谢：君の旅途、Sagilio，这两位佬的帮助。
