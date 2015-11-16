# -*-coding: utf-8 -*-
try:
    from HTMLParser import HTMLParser
except ImportError:
    from html.parser import HTMLParser

try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse


class HTMLPurifier(HTMLParser):
    """
    暂时无法过滤CSS，所以不要开启"style"属性。常见的 XSS:
        <embed allowscriptaccess="never">
        <img src="javascript:alert('XSS')">
        <img dynsrc="javascript:alert('XSS')">
        <img lowsrc="javascript:alert('XSS')">
        <input type="image" src="javascript:alert('XSS');">
        <body background="javascript:alert('XSS')">
        <bgsound src="javascript:alert('XSS');">
        <link rel="stylesheet" href="javascript:alert('XSS');">
        <style type="text/javascript">alert('XSS');</style>
        <meta http-equiv="refresh" content="0;url=javascript:alert('XSS');">
        <a href="javascript:alert('XSS')">
        <base href="javascript:alert('XSS');//">
        <iframe src="javascript:alert('XSS');"></iframe>
        <frameset><frame src="javascript:alert('XSS');"></frameset>
        <table background="javascript:alert('XSS')">
        <td background="javascript:alert('XSS')">
        <style>
            li {list-style-image:url("javascript:alert('XSS')")}
            div {background-image:url("javascript:alert('XSS')")}
            div {width:expression(alert('XSS'))};
            div {behavior:url("xss.htc")}
        </style>
        <!--[if gte IE 4]>
            <script>alert('xss');</script>
        <![endif]-->
    """
    __level = 0
    # 公共的属性
    __common_attrs = ['title', 'dir', 'class', 'id', 'lang']
    # 无需关闭的标签
    unclosed_tags = ['br', 'hr', 'img', 'meta', 'link', 'input']
    # 允许的 URL 协议
    url_schemes = ['http', 'https', 'ftp']
    # 值类型是 URL 的属性
    url_attrs = {
        '*': ['href', 'src', 'background'],
        'img': ['src', 'dynsrc', 'lowsrc'],
    }
    # 必须添加的属性值
    required_attrs = {
        'embed': {'allowscriptaccess': 'never'},
        'style': {'type': 'text/css'},
        'a': {'rel': 'nofollow'},
    }
    # 连同内容一起过滤的标签
    ignored_tags = ['style', 'script']
    # 白名单过滤
    whitelist = {
        'h1': __common_attrs,
        'h2': __common_attrs,
        'h3': __common_attrs,
        'h4': __common_attrs,
        'h5': __common_attrs,
        'h6': __common_attrs,
        'span': __common_attrs,
        'strong': __common_attrs,
        'code': __common_attrs,
        'em': __common_attrs,
        'i': __common_attrs,
        'ul': __common_attrs,
        'li': __common_attrs,
        'ol': __common_attrs,
        'blockquote': __common_attrs,
        'sup': __common_attrs,
        'sub': __common_attrs,
        'big': __common_attrs,
        'small': __common_attrs,
        'p': __common_attrs,
        'u': __common_attrs,
        's': __common_attrs,
        'br': [],
        'hr': [],
        'img': ['src', 'width', 'height', 'alt', 'align'] + __common_attrs,
        'a': ['href', 'title', 'rel', 'target'] + __common_attrs,
        'table': ['border', 'cellpadding', 'cellspacing', 'width', 'height'] + __common_attrs,
        'caption': ['align'] + __common_attrs,
        'thead': ['align', 'valign'] + __common_attrs,
        'tbody': ['align', 'valign'] + __common_attrs,
        'tr': ['align', 'valign'] + __common_attrs,
        'td': ['colspan', 'rowspan', 'width', 'height', 'align', 'valign'] + __common_attrs,
        'th': ['colspan', 'rowspan', 'width', 'height', 'align', 'valign'] + __common_attrs,
        'col': ['span', 'width', 'align', 'valign'] + __common_attrs,
        'colgroup': ['span', 'width', 'align', 'valign'] + __common_attrs,
    }

    def __sanitize_url(self, url):
        """
        过滤 URL
        """
        result = urlparse(url)
        if (result.scheme == '' and url[:1] in ['/', '#']) or result.scheme in self.url_schemes:
            return result.geturl()
        else:
            return ''

    @staticmethod
    def __value_escape(value):
        """
        转义属性值（引号内的字符串）
        """
        return value.replace('"', "&#34;")\
                    .replace("'", "&#39;")

    @staticmethod
    def __html_escape(value):
        """
        转义 HTML
        """
        return value.replace("&", "&amp;")\
                    .replace('"', "&quot;")\
                    .replace("<", "&lt;")\
                    .replace(">", "&gt;")

    def __attrs_str(self, tag, attrs):
        """
        格式化标签的属性
        """
        required_attrs = {}
        url_attrs = []
        whitelist_attrs = self.whitelist[tag]

        if tag in self.required_attrs:
            required_attrs.update(self.required_attrs[tag])
        if '*' in self.required_attrs:
            required_attrs.update(self.required_attrs['*'])
        if tag in self.url_attrs:
            url_attrs.extend(self.url_attrs[tag])
        if '*' in self.url_attrs:
            url_attrs.extend(self.url_attrs['*'])

        items = {}
        for attr in attrs:
            key = attr[0]
            value = attr[1] or ''
            if key in whitelist_attrs:
                if key in url_attrs and value:
                    value = self.__sanitize_url(value)
                attr_str = u'%s="%s"' % (key, self.__value_escape(value),) if value != '' else u'%s' % (key,)
                items[key] = attr_str
        for key, value in required_attrs.iteritems():
            attr_str = u'%s="%s"' % (key, self.__value_escape(value),) if value != '' else u'%s' % (key,)
            items[key] = attr_str

        attrs_str = u' '.join(items.values())
        if attrs_str:
            return u' ' + attrs_str
        return ''

    def __init__(self, whitelist=None, ignored_tags=None, required_attrs=None, url_schemes=None):
        """
        构造函数
        :param whitelist: 白名单
        :param ignored_tags: 需要整体忽略的标签
        :param required_attrs: 必须要添加的属性
        :param url_schemes: 允许的 URL 协议
        :return:
        """
        if isinstance(whitelist, dict):
            self.whitelist.update(whitelist)
        if isinstance(ignored_tags, list):
            self.ignored_tags.extend(ignored_tags)
        if isinstance(required_attrs, dict):
            self.required_attrs.update(required_attrs)
        if isinstance(url_schemes, dict):
            self.url_schemes.update(url_schemes)
        self.data = []
        HTMLParser.__init__(self)

    def feed(self, data):
        """
        输入 HTML
        """
        HTMLParser.feed(self, data)
        return self

    def close(self):
        """
        关闭输入
        """
        self.data = []
        return HTMLParser.close(self)

    def html(self):
        """
        获取过滤后的 HTML 代码
        """
        return u''.join(self.data)

    def handle_starttag(self, tag, attrs):
        """
        处理标签开启
        """
        if tag in self.ignored_tags:
            self.__level += 1
            return
        if tag in self.whitelist:
            attrs = self.__attrs_str(tag, attrs)
            self.data.append(u'<%s%s>' % (tag, attrs, ))

    def handle_endtag(self, tag):
        """
        处理标签闭合
        """
        if tag in self.ignored_tags:
            self.__level -= 1
            return
        if tag in self.unclosed_tags:
            return
        if tag in self.whitelist:
            self.data.append(u'</%s>' % tag)

    def handle_startendtag(self, tag, attrs):
        """
        处理非闭合标签
        """
        if tag in self.whitelist:
            attrs = self.__attrs_str(tag, attrs)
            self.data.append(u'<%s%s/>' % (tag, attrs, ))

    def handle_data(self, data):
        """
        处理内容
        """
        if not self.__level:
            self.data.append(self.__html_escape(data))

    def handle_entityref(self, name):
        """
        处理转义字符
        """
        self.data.append(u'&%s;' % (name,))

    def handle_charref(self, name):
        """
        处理转义字符
        """
        self.data.append(u'&#%s;' % (name,))

    def handle_comment(self, data):
        """
        不允许注释
        """
        pass

    def handle_decl(self, decl):
        """
        不允许 <!DOCTYPE html>
        """
        pass

    def handle_pi(self, data):
        """
        不允许 <?proc color='red'>
        """
        pass

    def unknown_decl(self, data):
        """
        不允许 <![...]>
        """
        pass

