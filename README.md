# HTMLPurifier
基于 HTMLParser 的 HTML 代码净化器。用于过滤用户提交的不安全的 HTML 代码，避免跨站脚本注入。

## 示例代码

    from html_purifier import *
    purifier = HTMLPurifier()
    purifier.feed('<script>alert()</script><a href="javascript:alert()">XSS</a><img src="javascript:alert()">')
    print(purifier.html())
