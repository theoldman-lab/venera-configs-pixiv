class Pixiv extends ComicSource {
    name = "Pixiv"

    key = "pixiv"

    version = "0.1.2"

    minAppVersion = "1.6.0"

    url = "https://cdn.jsdelivr.net/gh/venera-app/venera-configs@main/pixiv.js"

    BASE_API = "https://app-api.pixiv.net"

    BASE_OAUTH = "https://oauth.secure.pixiv.net"

    HASH_SALT = "28c1fdd170a5204386cb1313c7077b34f83e4aaf4aa829ce78c231e05b0bae2c"

    CLIENT_ID = "MOBrBDS8blbauoSck0ZfDbtuzpyT"

    CLIENT_SECRET = "lsACyCD94FhDUtGTXi3QzcFE2uU1hqtDaKeqrdwj"

    get apiHost() {
        return (this.loadSetting('apiHost') || "app-api.pixiv.net").replace(/^https?:\/\//, '').replace(/\/$/, '')
    }

    get baseUrl() {
        return "https://" + this.apiHost
    }

    get oauthHost() {
        return (this.loadSetting('oauthHost') || "oauth.secure.pixiv.net").replace(/^https?:\/\//, '').replace(/\/$/, '')
    }

    get oauthUrl() {
        return "https://" + this.oauthHost
    }

    isoTime() {
        return new Date().toISOString().split('.')[0] + '+00:00'
    }

    sign(time) {
        return Convert.hexEncode(Convert.md5(Convert.encodeUtf8(time + this.HASH_SALT)))
    }

    buildHeaders(auth = true, contentType = null) {
        let time = this.isoTime()
        let headers = {
            "X-Client-Time": time,
            "X-Client-Hash": this.sign(time),
            "User-Agent": "PixivAndroidApp/5.0.155 (Android 10.0; Pixel C)",
            "App-OS": "Android",
            "App-OS-Version": "Android 10.0",
            "App-Version": "5.0.166",
            "Accept-Language": "zh-CN",
        }
        if (contentType) {
            headers["Content-Type"] = contentType
        }
        if (auth) {
            let token = this.loadData('access_token')
            if (token) {
                headers["Authorization"] = "Bearer " + token
            }
        }
        return headers
    }

    buildQuery(params) {
        if (!params) return ''
        let parts = []
        for (let key in params) {
            let value = params[key]
            if (value === null || value === undefined || value === '') continue
            parts.push(`${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
        }
        return parts.length > 0 ? '?' + parts.join('&') : ''
    }

    async request(method, path, params, body, auth = true, contentType = null) {
        let url = this.baseUrl + path + this.buildQuery(params)
        let res = await Network.sendRequest(method, url, this.buildHeaders(auth, contentType), body)
        if (res.status === 400 && auth && res.body && res.body.indexOf('OAuth') >= 0 && this.loadData('refresh_token')) {
            await this.refreshToken()
            res = await Network.sendRequest(method, url, this.buildHeaders(auth, contentType), body)
        }
        return res
    }

    apiGet(path, params, auth = true) {
        return this.request('GET', path, params, null, auth)
    }

    apiPost(path, body, auth = true) {
        return this.request('POST', path, null, body, auth, "application/x-www-form-urlencoded")
    }

    check(res) {
        if (!res || res.status !== 200) {
            throw `Invalid status code: ${res ? res.status : 'no response'}`
        }
        return JSON.parse(res.body)
    }

    async refreshToken() {
        let refreshToken = this.loadData('refresh_token')
        if (!refreshToken) {
            throw 'Login expired'
        }
        let body = `client_id=${this.CLIENT_ID}&client_secret=${this.CLIENT_SECRET}` +
            `&grant_type=refresh_token&refresh_token=${encodeURIComponent(refreshToken)}&include_policy=true`
        let res = await Network.post(this.oauthUrl + '/auth/token', this.buildHeaders(false, "application/x-www-form-urlencoded"), body)
        if (res.status !== 200) {
            throw 'Login expired'
        }
        let json = JSON.parse(res.body)
        this.saveData('access_token', json.access_token)
        this.saveData('refresh_token', json.refresh_token)
        if (json.user) {
            this.saveData('user_id', String(json.user.id))
        }
    }

    preparePkce() {
        if (this.loginUrl) {
            return this.loginUrl
        }
        const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~'
        let verifier = ''
        for (let i = 0; i < 128; i++) {
            verifier += charset[randomInt(0, charset.length - 1)]
        }
        this.pkceVerifier = verifier
        let challenge = Convert.encodeBase64(Convert.sha256(Convert.encodeUtf8(verifier)))
            .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
        this.loginUrl = `${this.BASE_API}/web/v1/login?code_challenge=${challenge}&code_challenge_method=S256&client=pixiv-android`
        return this.loginUrl
    }

    init() {
        this.preparePkce()
        if (this.pkceVerifier) {
            this.saveData('pkce_verifier', this.pkceVerifier)
        }
    }

    account = (() => {
        const source = this
        return {
            login: async (account, pwd) => {
                let body = `client_id=${source.CLIENT_ID}&client_secret=${source.CLIENT_SECRET}` +
                    `&grant_type=password&username=${encodeURIComponent(account)}` +
                    `&password=${encodeURIComponent(pwd)}` +
                    `&Device_token=pixiv&get_secure_url=true&include_policy=true`
                let res = await Network.post(source.oauthUrl + '/auth/token',
                    source.buildHeaders(false, "application/x-www-form-urlencoded"), body)
                if (res.status !== 200) {
                    throw 'Login failed: ' + res.body
                }
                let json = JSON.parse(res.body)
                source.saveData('access_token', json.access_token)
                source.saveData('refresh_token', json.refresh_token)
                if (json.user) {
                    source.saveData('user_id', String(json.user.id))
                }
                return 'ok'
            },

            loginWithWebview: {
                get url() {
                    return source.preparePkce()
                },
                checkStatus: (url, title) => {
                    let match = url.match(/[?#&]code=([^&#]+)/)
                    if (match) {
                        if (source.pkceVerifier) {
                            source.saveData('pkce_verifier', source.pkceVerifier)
                        }
                        source.saveData('pkce_code', decodeURIComponent(match[1]))
                        return true
                    }
                    return false
                },
                onLoginSuccess: async () => {
                    let code = source.loadData('pkce_code')
                    let verifier = source.pkceVerifier || source.loadData('pkce_verifier')
                    if (!code || !verifier) {
                        throw 'Login failed: missing authorization code'
                    }
                    let body = `client_id=${source.CLIENT_ID}&client_secret=${source.CLIENT_SECRET}` +
                        `&grant_type=authorization_code&code=${encodeURIComponent(code)}` +
                        `&code_verifier=${encodeURIComponent(verifier)}` +
                        `&redirect_uri=${encodeURIComponent(source.BASE_API + '/web/v1/users/auth/pixiv/callback')}` +
                        `&include_policy=true`
                    let res = await Network.post(source.oauthUrl + '/auth/token', source.buildHeaders(false, "application/x-www-form-urlencoded"), body)
                    if (res.status !== 200) {
                        throw 'Login failed: ' + res.body
                    }
                    let json = JSON.parse(res.body)
                    source.saveData('access_token', json.access_token)
                    source.saveData('refresh_token', json.refresh_token)
                    if (json.user) {
                        source.saveData('user_id', String(json.user.id))
                    }
                    return 'ok'
                },
            },

            logout: () => {
                source.deleteData('access_token')
                source.deleteData('refresh_token')
                source.deleteData('user_id')
                source.deleteData('pkce_code')
            },

            registerWebsite: "https://accounts.pixiv.net/signup"
        }
    })()

    cleanCaption(html) {
        if (!html) return ""
        return html
            .replace(/<br\s*\/?>/gi, "\n")
            .replace(/<[^>]+>/g, "")
            .replace(/&amp;/g, "&")
            .replace(/&lt;/g, "<")
            .replace(/&gt;/g, ">")
            .replace(/&quot;/g, '"')
            .replace(/&#39;/g, "'")
    }

    pickPageUrl(urls, quality) {
        if (!urls) return null
        if (quality === 'original') {
            return urls.original || urls.large || urls.medium
        }
        return urls[quality] || urls.large || urls.medium
    }

    pickSingleUrl(illust, quality) {
        if (quality === 'original') {
            return (illust.meta_single_page && illust.meta_single_page.original_image_url) || (illust.image_urls && illust.image_urls.large)
        }
        return (illust.image_urls && (illust.image_urls[quality] || illust.image_urls.large)) || null
    }

    pickCover(illust) {
        let quality = this.loadSetting('imageQuality') || 'large'
        if (quality === 'original') {
            if (illust.meta_pages && illust.meta_pages.length > 0) {
                return illust.meta_pages[0].image_urls.original
            }
            return (illust.meta_single_page && illust.meta_single_page.original_image_url) || (illust.image_urls && illust.image_urls.large)
        }
        return (illust.image_urls && (illust.image_urls[quality] || illust.image_urls.large)) || null
    }

    rewriteHost(url) {
        if (!url) return url
        let mode = this.loadSetting('imageHost') || 'i.pximg.net'
        let host = mode
        if (mode === 'custom') {
            host = this.loadSetting('customImageHost') || 'i.pximg.net'
        }
        if (host === 'i.pximg.net') return url
        return url.replace(/\/\/i\.pximg\.net\//, '//' + host + '/')
    }

    parseComic(illust) {
        let tags = (illust.tags || []).map(tag => tag.name)
        return new Comic({
            id: String(illust.id),
            title: illust.title,
            subTitle: illust.user ? illust.user.name : "",
            cover: this.rewriteHost(this.pickCover(illust)),
            tags: tags,
            description: this.cleanCaption(illust.caption),
            maxPage: illust.page_count || 1,
        })
    }

    parseIllustList(json) {
        return (json.illusts || []).map(illust => this.parseComic(illust))
    }

    explore = [
        {
            title: "推荐插画",
            type: "multiPageComicList",
            load: async (page) => {
                let res = await this.apiGet('/v1/illust/recommended', {
                    filter: 'for_android',
                    include_ranking_label: true,
                })
                return { comics: this.parseIllustList(this.check(res)), maxPage: 1 }
            },
        },
        {
            title: "推荐漫画",
            type: "multiPageComicList",
            load: async (page) => {
                let res = await this.apiGet('/v1/manga/recommended', {
                    filter: 'for_android',
                    include_ranking_label: true,
                })
                return { comics: this.parseIllustList(this.check(res)), maxPage: 1 }
            },
        },
        {
            title: "关注新作",
            type: "multiPageComicList",
            load: async (page) => {
                if (!this.isLogged) {
                    throw 'Not logged in'
                }
                let res = await this.apiGet('/v2/illust/follow', { restrict: 'all' })
                return { comics: this.parseIllustList(this.check(res)), maxPage: 1 }
            },
        },
        {
            title: "综合日榜",
            type: "multiPageComicList",
            load: async (page) => {
                let res = await this.apiGet('/v1/illust/ranking', {
                    filter: 'for_android',
                    mode: 'day',
                })
                return { comics: this.parseIllustList(this.check(res)), maxPage: 1 }
            },
        },
        {
            title: "热门标签",
            type: "multiPageComicList",
            load: async (page) => {
                let res = await this.apiGet('/v1/trending-tags/illust', { filter: 'for_android' })
                let json = this.check(res)
                let comics = []
                for (let item of (json.trend_tags || [])) {
                    if (item.illust) {
                        comics.push(this.parseComic(item.illust))
                    }
                }
                return { comics: comics, maxPage: 1 }
            },
        },
    ]

    category = {
        title: "Pixiv",
        parts: [
            {
                name: "热门标签",
                type: "dynamic",
                loader: async () => {
                    let res = await this.apiGet('/v1/trending-tags/illust', { filter: 'for_android' })
                    let json = this.check(res)
                    let items = []
                    for (let item of (json.trend_tags || [])) {
                        items.push({
                            label: item.translated_name || item.tag,
                            target: {
                                page: 'category',
                                attributes: {
                                    category: 'tag',
                                    param: item.tag,
                                },
                            },
                        })
                    }
                    return items
                },
            },
        ],
        enableRankingPage: true,
    }

    categoryComics = {
        load: async (category, param, options, page) => {
            let res = await this.apiGet('/v1/search/illust', {
                filter: 'for_android',
                merge_plain_keyword_results: true,
                word: param || category,
                search_target: 'exact_match_for_tags',
                sort: 'date_desc',
            })
            return { comics: this.parseIllustList(this.check(res)), maxPage: 1 }
        },

        ranking: {
            options: [
                "day-日榜",
                "week-周榜",
                "month-月榜",
                "day_male-男性向日榜",
                "day_female-女性向日榜",
                "week_rookie-新人周榜",
                "week_original-原创周榜",
            ],
            load: async (option, page) => {
                let res = await this.apiGet('/v1/illust/ranking', {
                    filter: 'for_android',
                    mode: option,
                })
                return { comics: this.parseIllustList(this.check(res)), maxPage: 1 }
            },
        },
    }

    search = {
        load: async (keyword, options, page) => {
            let sort = options[0] || 'date_desc'
            let target = options[1] || 'partial_match_for_tags'
            let res = await this.apiGet('/v1/search/illust', {
                filter: 'for_android',
                merge_plain_keyword_results: true,
                word: keyword,
                sort: sort,
                search_target: target,
            })
            return { comics: this.parseIllustList(this.check(res)), maxPage: 1 }
        },

        optionList: [
            {
                label: "排序",
                options: [
                    "date_desc-最新",
                    "date_asc-最早",
                    "popular_desc-热门",
                ],
            },
            {
                label: "搜索范围",
                options: [
                    "partial_match_for_tags-标签(部分匹配)",
                    "exact_match_for_tags-标签(完整匹配)",
                    "title_and_caption-标题与简介",
                ],
            },
        ],
    }

    favorites = {
        multiFolder: true,

        addOrDelFavorite: async (comicId, folderId, isAdding, favoriteId) => {
            if (!this.isLogged) {
                throw 'Login expired'
            }
            let res
            if (isAdding) {
                res = await this.apiPost('/v2/illust/bookmark/add',
                    `illust_id=${encodeURIComponent(comicId)}&restrict=${encodeURIComponent(folderId || 'public')}`)
            } else {
                res = await this.apiPost('/v1/illust/bookmark/delete',
                    `illust_id=${encodeURIComponent(comicId)}`)
            }
            if (res.status === 401 || (res.status === 400 && res.body && res.body.indexOf('OAuth') >= 0)) {
                throw 'Login expired'
            }
            if (res.status !== 200) {
                throw 'Invalid status code: ' + res.status
            }
            return 'ok'
        },

        loadFolders: async (comicId) => {
            if (!this.isLogged) {
                throw 'Login expired'
            }
            let folders = {
                'public': '公开收藏',
                'private': '私密收藏',
            }
            let favorited = []
            if (comicId) {
                try {
                    let res = await this.apiGet('/v2/illust/bookmark/detail', { illust_id: comicId })
                    if (res.status === 200) {
                        let detail = JSON.parse(res.body).bookmark_detail
                        if (detail && detail.is_bookmarked) {
                            favorited = ['public']
                        }
                    }
                } catch (e) {
                }
            }
            return { folders: folders, favorited: favorited }
        },

        loadComics: async (page, folder) => {
            let userId = this.loadData('user_id')
            if (!userId) {
                throw 'Login expired'
            }
            let res = await this.apiGet('/v1/user/bookmarks/illust', {
                user_id: userId,
                restrict: folder || 'public',
                filter: 'for_android',
            })
            return { comics: this.parseIllustList(this.check(res)), maxPage: 1 }
        },

        singleFolderForSingleComic: false,
    }

    comic = {
        loadInfo: async (id) => {
            let detailRes = await this.apiGet('/v1/illust/detail', {
                illust_id: id,
                filter: 'for_android',
            })
            let json = this.check(detailRes)
            let illust = json.illust
            let related = []
            try {
                let relatedRes = await this.apiGet('/v2/illust/related', {
                    illust_id: id,
                    filter: 'for_android',
                })
                if (relatedRes.status === 200) {
                    related = this.parseIllustList(JSON.parse(relatedRes.body))
                }
            } catch (e) {
            }
            let tags = {}
            tags['标签'] = (illust.tags || []).map(tag => tag.name)
            let chapters = {}
            if ((illust.page_count || 1) > 1) {
                chapters['0'] = `1-${illust.page_count}`
            }
            return new ComicDetails({
                title: illust.title,
                subtitle: illust.user ? illust.user.name : "",
                cover: this.rewriteHost(this.pickCover(illust)),
                description: this.cleanCaption(illust.caption),
                tags: tags,
                chapters: chapters,
                isFavorite: illust.is_bookmarked || false,
                recommend: related,
                commentCount: illust.total_comments || 0,
                likesCount: illust.total_bookmarks || 0,
                uploader: illust.user ? illust.user.name : "",
                uploadTime: illust.create_date,
                updateTime: illust.create_date,
                url: `https://www.pixiv.net/artworks/${illust.id}`,
                maxPage: illust.page_count || 1,
            })
        },

        loadEp: async (comicId, epId) => {
            let res = await this.apiGet('/v1/illust/detail', {
                illust_id: comicId,
                filter: 'for_android',
            })
            let illust = this.check(res).illust
            let quality = this.loadSetting('imageQuality') || 'large'
            let images = []
            if (illust.meta_pages && illust.meta_pages.length > 0) {
                for (let page of illust.meta_pages) {
                    let url = this.pickPageUrl(page.image_urls, quality)
                    if (url) {
                        images.push(this.rewriteHost(url))
                    }
                }
            } else {
                let url = this.pickSingleUrl(illust, quality)
                if (url) {
                    images.push(this.rewriteHost(url))
                }
            }
            return { images: images }
        },

        onImageLoad: (url, comicId, epId) => {
            return {
                url: this.rewriteHost(url),
                headers: {
                    "referer": this.BASE_API + "/",
                    "user-agent": "PixivIOSApp/5.8.0",
                },
            }
        },

        onThumbnailLoad: (url) => {
            return {
                url: this.rewriteHost(url),
                headers: {
                    "referer": this.BASE_API + "/",
                    "user-agent": "PixivIOSApp/5.8.0",
                },
            }
        },

        loadComments: async (comicId, subId, page, replyTo) => {
            let comments = []
            if (replyTo) {
                let res = await this.apiGet('/v2/illust/comment/replies', { comment_id: replyTo })
                let json = this.check(res)
                for (let item of (json.comments || [])) {
                    comments.push(this.parseComment(item))
                }
            } else {
                let res = await this.apiGet('/v3/illust/comments', { illust_id: comicId })
                let json = this.check(res)
                for (let item of (json.comments || [])) {
                    comments.push(this.parseComment(item))
                }
            }
            return { comments: comments, maxPage: 1 }
        },

        idMatch: "^(\\d+)$",

        onClickTag: (namespace, tag) => {
            return {
                page: 'search',
                attributes: {
                    keyword: tag,
                },
            }
        },

        link: {
            domains: [
                'pixiv.net',
                'www.pixiv.net',
            ],
            linkToId: (url) => {
                let match = url.match(/artworks\/(\d+)/) || url.match(/[?&]illust_id=(\d+)/)
                return match ? match[1] : null
            },
        },
    }

    parseComment(item) {
        let user = item.user || {}
        let profile = user.profile_image_urls || {}
        return new Comment({
            userName: user.name || "",
            avatar: profile.medium ? this.rewriteHost(profile.medium) : undefined,
            content: item.comment || "",
            time: item.date,
            replyCount: item.has_replies ? 1 : 0,
            id: item.id !== undefined ? String(item.id) : undefined,
        })
    }

    settings = {
        apiHost: {
            title: "API 地址",
            type: "input",
            validator: null,
            default: "app-api.pixiv.net",
        },
        oauthHost: {
            title: "OAuth 地址",
            type: "input",
            validator: null,
            default: "oauth.secure.pixiv.net",
        },
        imageQuality: {
            title: "图片质量",
            type: "select",
            options: [
                { value: 'medium', text: '中' },
                { value: 'large', text: '大' },
                { value: 'original', text: '原图' },
            ],
            default: 'large',
        },
        imageHost: {
            title: "图片域名",
            type: "select",
            options: [
                { value: 'i.pximg.net', text: 'i.pximg.net' },
                { value: 'i.pixiv.re', text: 'i.pixiv.re' },
                { value: 'custom', text: '自定义' },
            ],
            default: 'i.pximg.net',
        },
        customImageHost: {
            title: "自定义图片域名",
            type: "input",
            validator: null,
            default: "",
        },
    }

    translation = {
        'zh_CN': {
            '推荐插画': '推荐插画',
            '推荐漫画': '推荐漫画',
            '关注新作': '关注新作',
            '综合日榜': '综合日榜',
            '热门标签': '热门标签',
            'Pixiv': 'Pixiv',
            '排序': '排序',
            '搜索范围': '搜索范围',
            '最新': '最新',
            '最早': '最早',
            '热门': '热门',
            '标签(部分匹配)': '标签(部分匹配)',
            '标签(完整匹配)': '标签(完整匹配)',
            '标题与简介': '标题与简介',
            '日榜': '日榜',
            '周榜': '周榜',
            '月榜': '月榜',
            '男性向日榜': '男性向日榜',
            '女性向日榜': '女性向日榜',
            '新人周榜': '新人周榜',
            '原创周榜': '原创周榜',
            '公开收藏': '公开收藏',
            '私密收藏': '私密收藏',
            '标签': '标签',
            'API 地址': 'API 地址',
            'OAuth 地址': 'OAuth 地址',
            '图片质量': '图片质量',
            '图片域名': '图片域名',
            '中': '中',
            '大': '大',
            '原图': '原图',
            '自定义': '自定义',
            '自定义图片域名': '自定义图片域名',
        },
        'zh_TW': {
            '推荐插画': '推薦插畫',
            '推荐漫画': '推薦漫畫',
            '关注新作': '關注新作',
            '综合日榜': '綜合日榜',
            '热门标签': '熱門標籤',
            '排序': '排序',
            '搜索范围': '搜尋範圍',
            '最新': '最新',
            '最早': '最早',
            '热门': '熱門',
            '标签(部分匹配)': '標籤(部分匹配)',
            '标签(完整匹配)': '標籤(完整匹配)',
            '标题与简介': '標題與簡介',
            '日榜': '日榜',
            '周榜': '週榜',
            '月榜': '月榜',
            '男性向日榜': '男性向日榜',
            '女性向日榜': '女性向日榜',
            '新人周榜': '新人週榜',
            '原创周榜': '原創週榜',
            '公开收藏': '公開收藏',
            '私密收藏': '私密收藏',
            '标签': '標籤',
            'API 地址': 'API 位址',
            'OAuth 地址': 'OAuth 位址',
            '图片质量': '圖片品質',
            '图片域名': '圖片網域',
            '中': '中',
            '大': '大',
            '原图': '原圖',
            '自定义': '自訂',
            '自定义图片域名': '自訂圖片網域',
        },
        'en': {
            '推荐插画': 'Recommended Illustrations',
            '推荐漫画': 'Recommended Manga',
            '关注新作': 'Following',
            '综合日榜': 'Daily Ranking',
            '热门标签': 'Trending Tags',
            '排序': 'Sort',
            '搜索范围': 'Search Target',
            '最新': 'Newest',
            '最早': 'Oldest',
            '热门': 'Popular',
            '标签(部分匹配)': 'Tags (partial)',
            '标签(完整匹配)': 'Tags (exact)',
            '标题与简介': 'Title & Caption',
            '日榜': 'Daily',
            '周榜': 'Weekly',
            '月榜': 'Monthly',
            '男性向日榜': 'Daily Male',
            '女性向日榜': 'Daily Female',
            '新人周榜': 'Weekly Rookie',
            '原创周榜': 'Weekly Original',
            '公开收藏': 'Public',
            '私密收藏': 'Private',
            '标签': 'Tags',
            'API 地址': 'API Host',
            'OAuth 地址': 'OAuth Host',
            '图片质量': 'Image Quality',
            '图片域名': 'Image Host',
            '中': 'Medium',
            '大': 'Large',
            '原图': 'Original',
            '自定义': 'Custom',
            '自定义图片域名': 'Custom Image Host',
        },
    }
}
