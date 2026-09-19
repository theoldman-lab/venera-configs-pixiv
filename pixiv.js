class Pixiv extends ComicSource {
    name = "Pixiv"

    key = "pixiv"

    version = "0.2.0"

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

    fixNextUrl(url) {
        if (!url) return url
        return url.replace(/^https?:\/\/[^/]+/, this.baseUrl)
    }

    needRefresh(res) {
        if (!res) return false
        if (res.status === 401) return !!this.loadData('refresh_token')
        if (res.status === 400 && res.body && res.body.indexOf('OAuth') >= 0) {
            return !!this.loadData('refresh_token')
        }
        return false
    }

    async request(method, path, params, body, auth = true, contentType = null) {
        let url = /^https?:\/\//.test(path) ? path : this.baseUrl + path
        url += this.buildQuery(params)
        let res = await Network.sendRequest(method, url, this.buildHeaders(auth, contentType), body)
        if (auth && this.needRefresh(res)) {
            await this.ensureRefresh()
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

    apiDelete(path, params, auth = true) {
        return this.request('DELETE', path, params, null, auth)
    }

    check(res) {
        if (!res || res.status !== 200) {
            let detail = res && res.body ? String(res.body).substring(0, 300) : ''
            throw `Invalid status code: ${res ? res.status : 'no response'}${detail ? ' - ' + detail : ''}`
        }
        return JSON.parse(res.body)
    }

    assertOk(res, message = 'Request failed') {
        if (!res) {
            throw message
        }
        if (res.status === 401 || (res.status === 400 && res.body && res.body.indexOf('OAuth') >= 0)) {
            throw 'Login expired'
        }
        if (res.status !== 200) {
            let detail = res.body ? String(res.body).substring(0, 300) : ''
            throw `${message}: ${res.status}${detail ? ' - ' + detail : ''}`
        }
        return 'ok'
    }

    async loadIllustPage(next, path, params) {
        let res = await this.apiGet(next || path, next ? null : params)
        let json = this.check(res)
        return {
            comics: this.parseIllustList(json),
            next: json.next_url ? this.fixNextUrl(json.next_url) : null,
        }
    }

    ensureRefresh() {
        if (!this._refreshPromise) {
            this._refreshPromise = this.refreshToken().then(
                (v) => {
                    this._refreshPromise = null
                    return v
                },
                (e) => {
                    this._refreshPromise = null
                    throw e
                }
            )
        }
        return this._refreshPromise
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

    parseAuthError(body) {
        if (!body) return 'unknown error'
        try {
            let json = JSON.parse(body)
            if (json.errors) {
                for (let key in json.errors) {
                    let err = json.errors[key]
                    if (err && err.message) return err.message
                }
            }
            if (json.error) return json.error
        } catch (e) {
        }
        return String(body).substring(0, 300)
    }

    saveToken(json) {
        this.saveData('access_token', json.access_token)
        this.saveData('refresh_token', json.refresh_token)
        if (json.user) {
            this.saveData('user_id', String(json.user.id))
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
                    let msg = source.parseAuthError(res.body)
                    if (/captcha|verify|challenge/i.test(msg)) {
                        msg += ' (Pixiv 要求人机验证, 请改用网页登录)'
                    }
                    throw 'Login failed: ' + msg
                }
                source.saveToken(JSON.parse(res.body))
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
                        throw 'Login failed: ' + source.parseAuthError(res.body)
                    }
                    source.saveToken(JSON.parse(res.body))
                    return 'ok'
                },
            },

            logout: () => {
                source.deleteData('access_token')
                source.deleteData('refresh_token')
                source.deleteData('user_id')
                source.deleteData('pkce_code')
                source.deleteData('pkce_verifier')
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
            loadNext: (next) => this.loadIllustPage(next, '/v1/illust/recommended', {
                filter: 'for_android',
                include_ranking_label: true,
            }),
        },
        {
            title: "推荐漫画",
            type: "multiPageComicList",
            loadNext: (next) => this.loadIllustPage(next, '/v1/manga/recommended', {
                filter: 'for_android',
                include_ranking_label: true,
            }),
        },
        {
            title: "关注新作",
            type: "multiPageComicList",
            loadNext: async (next) => {
                if (!this.isLogged) {
                    throw 'Not logged in'
                }
                return this.loadIllustPage(next, '/v2/illust/follow', { restrict: 'all' })
            },
        },
        {
            title: "综合日榜",
            type: "multiPageComicList",
            loadNext: (next) => this.loadIllustPage(next, '/v1/illust/ranking', {
                filter: 'for_android',
                mode: 'day',
            }),
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

    pagedMax(json, page) {
        return json && json.next_url ? page + 1 : page
    }

    async resolveUserId(nameOrId) {
        if (/^\d+$/.test(String(nameOrId))) {
            return String(nameOrId)
        }
        let res = await this.apiGet('/v1/search/user', {
            filter: 'for_android',
            word: nameOrId,
        })
        let json = this.check(res)
        let previews = json.user_previews || []
        if (previews.length > 0 && previews[0].user) {
            return String(previews[0].user.id)
        }
        return null
    }

    categoryComics = {
        load: async (category, param, options, page) => {
            let offset = (page - 1) * 30
            let sort = (options && options[0]) || 'date_desc'
            if (category === 'artist') {
                let userId = await this.resolveUserId(param)
                if (!userId) {
                    return { comics: [], maxPage: page }
                }
                let res = await this.apiGet('/v1/user/illusts', {
                    filter: 'for_android',
                    user_id: userId,
                    type: 'illust',
                    offset: offset || null,
                })
                let json = this.check(res)
                return { comics: this.parseIllustList(json), maxPage: this.pagedMax(json, page) }
            }
            let res = await this.apiGet('/v1/search/illust', {
                filter: 'for_android',
                merge_plain_keyword_results: true,
                word: param || category,
                search_target: 'exact_match_for_tags',
                sort: sort,
                offset: offset || null,
            })
            let json = this.check(res)
            return { comics: this.parseIllustList(json), maxPage: this.pagedMax(json, page) }
        },

        optionList: [
            {
                label: "排序",
                options: [
                    "date_desc-最新",
                    "date_asc-最早",
                    "popular_desc-热门",
                ],
                notShowWhen: ['artist'],
            },
        ],

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
                let offset = (page - 1) * 30
                let res = await this.apiGet('/v1/illust/ranking', {
                    filter: 'for_android',
                    mode: option,
                    offset: offset || null,
                })
                let json = this.check(res)
                return { comics: this.parseIllustList(json), maxPage: this.pagedMax(json, page) }
            },
        },
    }

    search = {
        loadNext: async (keyword, options, next) => {
            let sort = options[0] || 'date_desc'
            let target = options[1] || 'partial_match_for_tags'
            let res = await this.apiGet(next || '/v1/search/illust', next ? null : {
                filter: 'for_android',
                merge_plain_keyword_results: true,
                word: keyword,
                sort: sort,
                search_target: target,
            })
            let json = this.check(res)
            return {
                comics: this.parseIllustList(json),
                next: json.next_url ? this.fixNextUrl(json.next_url) : null,
            }
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

        enableTagsSuggestions: true,

        onTagSuggestionSelected: (namespace, tag) => tag,
    }

    tagFolderId(restrict, name) {
        return 'tag:' + (restrict || 'public') + ':' + name
    }

    parseTagFolder(folderId) {
        if (!folderId || folderId.indexOf('tag:') !== 0) return null
        let rest = folderId.substring(4)
        let idx = rest.indexOf(':')
        if (idx < 0) return null
        return { restrict: rest.substring(0, idx), name: rest.substring(idx + 1) }
    }

    buildBookmarkBody(comicId, restrict, tags) {
        let body = `illust_id=${encodeURIComponent(comicId)}&restrict=${encodeURIComponent(restrict || 'public')}`
        for (let tag of (tags || [])) {
            body += `&tags[]=${encodeURIComponent(tag)}`
        }
        return body
    }

    async getBookmarkDetail(comicId) {
        let res = await this.apiGet('/v2/illust/bookmark/detail', { illust_id: comicId })
        if (res.status !== 200) {
            return null
        }
        return JSON.parse(res.body).bookmark_detail || null
    }

    favorites = {
        multiFolder: true,

        addOrDelFavorite: async (comicId, folderId, isAdding, favoriteId) => {
            if (!this.isLogged) {
                throw 'Login expired'
            }
            let parts = this.parseTagFolder(folderId)
            if (!isAdding) {
                if (!parts) {
                    let res = await this.apiPost('/v1/illust/bookmark/delete',
                        `illust_id=${encodeURIComponent(comicId)}`)
                    return this.assertOk(res, 'Failed to delete favorite')
                }
                let detail = await this.getBookmarkDetail(comicId)
                if (!detail || !detail.is_bookmarked) {
                    return 'ok'
                }
                let remaining = (detail.tags || [])
                    .map(t => t.name)
                    .filter(n => n !== parts.name)
                let res = await this.apiPost('/v2/illust/bookmark/add',
                    this.buildBookmarkBody(comicId, detail.restrict || parts.restrict || 'public', remaining))
                return this.assertOk(res, 'Failed to update favorite')
            }
            if (!parts) {
                let detail = await this.getBookmarkDetail(comicId)
                let tags = detail && detail.is_bookmarked ? (detail.tags || []).map(t => t.name) : []
                let res = await this.apiPost('/v2/illust/bookmark/add',
                    this.buildBookmarkBody(comicId, folderId, tags))
                return this.assertOk(res, 'Failed to add favorite')
            }
            let detail = await this.getBookmarkDetail(comicId)
            let restrict = detail && detail.is_bookmarked && detail.restrict ? detail.restrict : parts.restrict
            let tags = detail && detail.is_bookmarked ? (detail.tags || []).map(t => t.name) : []
            if (tags.indexOf(parts.name) < 0) {
                tags.push(parts.name)
            }
            let res = await this.apiPost('/v2/illust/bookmark/add',
                this.buildBookmarkBody(comicId, restrict, tags))
            return this.assertOk(res, 'Failed to add favorite')
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
            let detail = null
            if (comicId) {
                try {
                    detail = await this.getBookmarkDetail(comicId)
                } catch (e) {
                }
            }
            let userId = this.loadData('user_id')
            for (let restrict of ['public', 'private']) {
                try {
                    let res = await this.apiGet('/v1/user/bookmark-tags/illust', {
                        user_id: userId || null,
                        restrict: restrict,
                    })
                    if (res.status === 200) {
                        let json = JSON.parse(res.body)
                        for (let tag of (json.bookmark_tags || [])) {
                            folders[this.tagFolderId(restrict, tag.name)] = `${tag.name} (${tag.count})`
                        }
                    }
                } catch (e) {
                }
            }
            if (detail && detail.is_bookmarked) {
                let restrict = detail.restrict || 'public'
                favorited.push(restrict)
                for (let tag of (detail.tags || [])) {
                    favorited.push(this.tagFolderId(restrict, tag.name))
                }
            }
            return { folders: folders, favorited: favorited }
        },

        addFolder: async (name) => {
            let res = await this.apiPost('/v1/user/bookmark-tags/illust',
                `tag=${encodeURIComponent(name)}&restrict=public`)
            return this.assertOk(res, 'Failed to add folder')
        },

        deleteFolder: async (folderId) => {
            let parts = this.parseTagFolder(folderId)
            if (!parts) {
                throw 'Invalid folder'
            }
            let res = await this.apiDelete('/v1/user/bookmark-tags/illust', {
                tag: parts.name,
                restrict: parts.restrict,
            })
            return this.assertOk(res, 'Failed to delete folder')
        },

        loadNext: async (next, folder) => {
            let userId = this.loadData('user_id')
            if (!userId) {
                throw 'Login expired'
            }
            let restrict = 'public'
            let tag = null
            let parts = this.parseTagFolder(folder)
            if (parts) {
                restrict = parts.restrict
                tag = parts.name
            } else if (folder === 'private') {
                restrict = 'private'
            }
            let res = await this.apiGet(next || '/v1/user/bookmarks/illust', next ? null : {
                user_id: userId,
                restrict: restrict,
                tag: tag,
                filter: 'for_android',
            })
            let json = this.check(res)
            return {
                comics: this.parseIllustList(json),
                next: json.next_url ? this.fixNextUrl(json.next_url) : null,
            }
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
            if (illust.user) {
                tags['作者'] = [illust.user.name]
            }
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

        loadThumbnails: async (id, next) => {
            let res = await this.apiGet('/v1/illust/detail', {
                illust_id: id,
                filter: 'for_android',
            })
            let illust = this.check(res).illust
            let quality = this.loadSetting('imageQuality') || 'large'
            let thumbQuality = quality === 'original' ? 'large' : quality
            let thumbnails = []
            if (illust.meta_pages && illust.meta_pages.length > 0) {
                for (let page of illust.meta_pages) {
                    let url = this.pickPageUrl(page.image_urls, thumbQuality)
                    if (url) {
                        thumbnails.push(this.rewriteHost(url))
                    }
                }
            }
            return { thumbnails: thumbnails, next: null }
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
            let json
            if (replyTo) {
                let res = await this.apiGet('/v2/illust/comment/replies', {
                    comment_id: replyTo,
                    offset: page > 1 ? (page - 1) * 20 : null,
                })
                json = this.check(res)
            } else {
                let res = await this.apiGet('/v3/illust/comments', {
                    illust_id: comicId,
                    offset: page > 1 ? (page - 1) * 20 : null,
                })
                json = this.check(res)
            }
            for (let item of (json.comments || [])) {
                comments.push(this.parseComment(item))
            }
            return { comments: comments, maxPage: json.next_url ? page + 1 : page }
        },

        sendComment: async (comicId, subId, content, replyTo) => {
            if (!this.isLogged) {
                throw 'Login expired'
            }
            let body = `illust_id=${encodeURIComponent(comicId)}&comment=${encodeURIComponent(content)}`
            if (replyTo) {
                body += `&parent_comment_id=${encodeURIComponent(replyTo)}`
            }
            let res = await this.apiPost('/v1/illust/comment/add', body)
            return this.assertOk(res, 'Failed to send comment')
        },

        idMatch: "^(\\d+)$",

        onClickTag: (namespace, tag) => {
            if (namespace === '作者') {
                return {
                    page: 'category',
                    attributes: {
                        category: 'artist',
                        param: tag,
                    },
                }
            }
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

        enableTagsTranslate: true,
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
            '作者': '作者',
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
            '作者': '作者',
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
            '作者': 'Artist',
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
