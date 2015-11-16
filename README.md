# HTMLPurifier
基于 HTMLParser 的 HTML 代码净化器。用于过滤用户提交的不安全的 HTML 代码，避免跨站脚本注入。

## 示例代码

    from html_purifier import *
    purifier = HTMLPurifier()
    purifier.feed(`<script>alert()</script><a href="javascript:alert()">XSS</a><img src="javascript:alert()">`)
    print(purifier.html())

    
## 说明

默认允许的 HTML 标签： `h1`, `h2`, `h3`, `h4`, `h5`, `h6`, `span`, `strong`, `code`, `em`, `b`, `i`, `dl`, `dt`, `dd`, `ul`, `ol`, `li`, `blockquote`, `sup`, `sub`, `big`, `small`, `p`, `u`, `s`, `br`, `hr`, `img`, `a`, `table`, `caption`, `thead`, `tbody`, `tr`, `td`, `th`, `col`, `colgroup`

由于不支持 CSS 过滤，所以请不要开启 `<style>` 标签和 `style` 属性的支持。 

所有标签的 `href`, `src`, `background` 属性值，以及 `<img>` 标签的 `dynsrc`, `lowsrc` 属性值被视作 URL 类型。URL 类型会做特殊处理，规则如下：

- 对于完整的 URL ，只允许 `url_schemes` 中定义过的协议；
- 对于非完整的 URL ，只允许以 "/" 开头的绝对路径和以 "#" 开头的锚点。
