// Sarcastic replies for links that aren't a LinkedIn profile photo. Matched on hostname suffix,
// first match wins, so specific entries sit above broad ones. Voice: the user's "that ain't it,
// chief. This here is LinkedIn property" energy, always steering back to the LinkedIn profile photo.
const Roasts = (() => {
  const pick = (xs) => xs[Math.floor(Math.random() * xs.length)];

  const STATE = [
    "STATE? This ain't state property, this is private property",
    "State? I ain't ever heard of that fool in my life",
  ];

  const TABLE = [
    // LinkedIn's own odds and ends
    [['static.licdn.com'], "That's the gray ghost default avatar, chief. LinkedIn property, sure, but upload a real face first"],
    // Microsoft
    [['yammer.com', 'engage.cloud.microsoft', 'web.yammer.com'], "Yammer just isn't it, chief. This here is LinkedIn property"],
    [['teams.microsoft.com', 'teams.live.com', 'teams.cloud.microsoft'], 'Teams? Your status says Away and so does your reading comprehension. This here is for LinkedIn profile photos'],
    [['sharepoint.com'], "SharePoint? Nobody, and I mean nobody, wants to request access to your face. LinkedIn profile photo URL, chief"],
    [['onedrive.live.com', '1drv.ms'], "OneDrive wants me to sign in. I ain't signing into nothing. LinkedIn profile photo URL, please"],
    [['hotmail.com', 'msn.com', 'yahoo.com', 'ask.com', 'altavista.com', 'excite.com', 'lycos.com'], "Really? Who even still uses that? This here needs your LinkedIn profile photo URL"],
    [['outlook.com', 'outlook.office.com', 'outlook.live.com', 'live.com', 'mail.google.com', 'gmail.com'], "That's your inbox, chief. I'm a honeypot, not the NSA. Show me that LinkedIn profile photo"],
    [['copilot.microsoft.com'], "Copilot can write your cover letter, but it can't be your face. LinkedIn profile photo URL, chief"],
    [['bing.com'], "Bing? Nobody has ever pasted a Bing link on purpose. Microsoft owns LinkedIn too, but that's the wrong kid, chief"],
    [['microsoft.com', 'office.com', 'microsoft365.com'], 'Same daddy company, wrong kid. This here is for LinkedIn profile photos'],
    [['xbox.com'], "Your gamerpic is a Master Chief helmet. That ain't it, chief"],
    [['blob.core.windows.net', 'azureedge.net'], 'A random Azure blob? Somebody\'s cloud bill is crying. LinkedIn profile photo URL, chief'],
    // Google
    [['googleusercontent.com', 'ggpht.com'], "That's your Google profile pic, chief. Right face, wrong network. LinkedIn profile photo URL"],
    [['drive.google.com', 'docs.google.com', 'photos.google.com', 'photos.app.goo.gl', 'goo.gl'], "Google Drive wants permissions. You want a job. Neither is happening here. Paste your LinkedIn profile photo URL"],
    [['gstatic.com'], "That's a Google Images thumbnail of somebody. Is it you? Be honest. LinkedIn profile photo URL, chief"],
    [['youtube.com', 'youtu.be', 'ytimg.com'], 'Like and subscribe? Nah. Copy image address on your LinkedIn profile photo, chief'],
    [['gemini.google.com', 'bard.google.com'], "Really? A clanker headshot? You're cooked. LinkedIn profile photo URL, man"],
    // Meta
    [['facebook.com', 'fb.com', 'fbcdn.net', 'messenger.com', 'fb.me'], "Really? Who even still uses that? This here needs your LinkedIn profile photo URL"],
    [['instagram.com', 'cdninstagram.com', 'instagr.am'], "Wow, very Gen Z of you, but this here needs your LinkedIn profile photo URL"],
    [['threads.net', 'threads.com'], "Threads? Nobody saw that post, and nobody's gonna see this frame either. LinkedIn profile photo URL, chief"],
    [['whatsapp.com', 'whatsapp.net', 'wa.me'], "This ain't the group chat, chief. LinkedIn profile photo URL, please"],
    // the rest of social
    [['twitter.com', 'x.com', 'twimg.com', 't.co'], "Posting on X ain't gonna get you hired, chief. Show me that LinkedIn profile photo"],
    [['tiktok.com', 'tiktokcdn.com', 'tiktokcdn-us.com', 'tiktokv.com'], "Wow, very Gen Z of you, but this here needs your LinkedIn profile photo URL"],
    [['snapchat.com', 'sc-cdn.net', 'snap.com'], "Wow, very Gen Z of you, but this here needs your LinkedIn profile photo URL"],
    [['reddit.com', 'redd.it', 'redditmedia.com', 'redditstatic.com'], "Reddit avatar? That's a cartoon of you, chief. This here is for real LinkedIn profile photos"],
    [['discord.com', 'discord.gg', 'discordapp.com', 'discordapp.net'], 'Your Discord pfp is an anime character and we both know it. LinkedIn profile photo URL, chief'],
    [['slack.com', 'slack-edge.com', 'slack-files.com', 'slack-imgs.com'], "A Slack link? Ping me back when it's your LinkedIn profile photo URL"],
    [['zoom.us', 'zoom.com'], "You're on mute, chief. Also that ain't your LinkedIn profile photo"],
    [['t.me', 'telegram.org', 'telegram.me'], "Telegram? Let's keep the espionage in the footer, chief. LinkedIn profile photo URL"],
    [['pinterest.com', 'pinimg.com', 'pin.it'], "That's a mood board, chief. Your face ain't aesthetic inspiration yet. LinkedIn profile photo URL"],
    [['tumblr.com', 'myspace.com', 'aol.com', 'aim.com', 'photobucket.com', 'deviantart.com', 'livejournal.com', 'xanga.com', 'angelfire.com', 'tripod.com', 'skype.com', 'icq.com', 'friendster.com', 'hi5.com', 'orkut.com', 'vine.co', 'picasaweb.google.com'], "Really? Who even still uses that? This here needs your LinkedIn profile photo URL"],
    [['bsky.app', 'bsky.social', 'cdn.bsky.app', 'bsky.network'], "Bluesky? I know you REEEALLY don't like Musk (I get it), but that ain't it, chief. This here is for LinkedIn URLs"],
    [['mastodon.social', 'mstdn.social'], "Mastodon? Bless your federated heart, but that ain't it, chief. This here is for LinkedIn URLs"],
    [['vk.com', 'weibo.com', 'qq.com'], 'Wrong side of the Great Firewall, chief. This here is LinkedIn property'],
    [['medium.com', 'substack.com', 'substackcdn.com'], 'Your thought leadership has been noted and ignored. Now paste your LinkedIn profile photo URL'],
    [['linktr.ee', 'beacons.ai', 'bio.link'], 'A link to your links? Chief. One link. The LinkedIn profile photo one'],
    // image hosts and stock
    [['imgur.com'], "Imgur? Yeah this is a meme, but the photo still gotta come from LinkedIn, chief"],
    [['giphy.com', 'tenor.com', 'gfycat.com'], 'A GIF? Your profile photo should move recruiters, not move. LinkedIn profile photo URL, chief'],
    [['flickr.com', 'staticflickr.com'], "Really? Who even still uses that? This here needs your LinkedIn profile photo URL"],
    [['unsplash.com', 'pexels.com', 'pixabay.com'], "That's a stock photo of a stranger. Honestly very LinkedIn, but that ain't it, chief"],
    [['shutterstock.com', 'gettyimages.com', 'istockphoto.com', 'stock.adobe.com', 'dreamstime.com', 'alamy.com', '123rf.com', 'depositphotos.com'], 'Stock photo with the watermark still on? Peak LinkedIn energy, still not your LinkedIn profile photo, chief'],
    [['thispersondoesnotexist.com', 'generated.photos'], "That person doesn't exist, chief. Neither will your job offer. LinkedIn profile photo URL"],
    [['chatgpt.com', 'openai.com', 'oaiusercontent.com', 'midjourney.com', 'claude.ai', 'anthropic.com', 'leonardo.ai', 'ideogram.ai', 'stability.ai', 'civitai.com', 'huggingface.co'], "Really? A clanker headshot? You're cooked. LinkedIn profile photo URL, man"],
    [['wikipedia.org', 'wikimedia.org', 'wikidata.org', 'wikiquote.org', 'wiktionary.org', 'wikinews.org', 'wikibooks.org', 'wikisource.org', 'wikiversity.org', 'wikivoyage.org', 'mediawiki.org', 'wikimediafoundation.org', 'fandom.com', 'wikia.com', 'wikia.nocookie.net', 'wikihow.com', 'whimg.com'], "That's a wiki photo. If you're famous, you don't need this tool, you'll be targeted soon enough. Otherwise, LinkedIn profile photo URL, chief"],
    [['gravatar.com'], 'Gravatar? What is this, 2009? LinkedIn profile photo URL, chief'],
    [['githubusercontent.com', 'github.com', 'github.io'], "Your GitHub avatar is a pixelated identicon and we both know it. That ain't it, chief"],
    [['gitlab.com', 'bitbucket.org'], "Commit history ain't a headshot, chief. Push your LinkedIn profile photo URL"],
    [['canva.com'], 'Canva made it cute. LinkedIn makes it official. LinkedIn profile photo URL, chief'],
    [['figma.com', 'notion.so', 'notion.site', 'miro.com'], "That's a design file, chief, not a face. LinkedIn profile photo URL"],
    // storage and sharing
    [['dropbox.com', 'dropboxusercontent.com', 'db.tt'], "Dropbox wants me to sign up. I ain't signing up for nothing. LinkedIn profile photo URL, chief"],
    [['box.com', 'wetransfer.com', 'we.tl', 'mega.nz', 'mediafire.com', 'sendspace.com'], "This ain't a file drop, chief, it's a honeypot. LinkedIn profile photo URL"],
    [['icloud.com'], "iCloud? Chief, don't give me your Apple ID. Give me your LinkedIn profile photo URL"],
    [['apple.com'], 'Think different. Also think LinkedIn profile photo URL, chief'],
    [['amazonaws.com', 'cloudfront.net'], 'A random S3 bucket? On a honeypot? In this economy? LinkedIn profile photo URL, chief'],
    [['amazon.com', 'amzn.to', 'media-amazon.com', 'ssl-images-amazon.com'], "That's an Amazon listing, chief. You ain't for sale. Yet. LinkedIn profile photo URL"],
    [['ebay.com', 'ebayimg.com', 'etsy.com', 'etsystatic.com'], "We ain't buying it, chief. Literally. LinkedIn profile photo URL"],
    [['cloudflare.com', 'imagedelivery.net', 'workers.dev', 'pages.dev', 'trycloudflare.com'], 'Nice Cloudflare link. Same, honestly. Still need your LinkedIn profile photo URL, chief'],
    [['wordpress.com', 'wp.com', 'wix.com', 'wixstatic.com', 'squarespace.com', 'squarespace-cdn.com', 'cdn.shopify.com', 'carrd.co'], "Your personal website is lovely, chief. Nobody's visiting it. LinkedIn profile photo URL"],
    // job sites
    [['glassdoor.com'], 'Glassdoor reviews you anonymously. LinkedIn judges you by name. We need the judgy one, chief'],
    [['myworkdayjobs.com', 'workday.com'], "Workday? Haven't you suffered enough? Paste your LinkedIn profile photo URL and rest, chief"],
    [['indeed.com', 'ziprecruiter.com', 'monster.com', 'careerbuilder.com', 'simplyhired.com', 'dice.com', 'wellfound.com', 'angel.co', 'joinhandshake.com', 'builtin.com', 'otta.com', 'hired.com'], 'Wrong job board, chief. This is #OPENTOHONEYPOTS, not #OPENTOWHATEVERTHATWAS. LinkedIn profile photo URL'],
    [['levels.fyi', 'teamblind.com'], "Your comp ain't your headshot, chief. Though it's probably just as sad. LinkedIn profile photo URL"],
    [['upwork.com', 'fiverr.com', 'freelancer.com', 'toptal.com'], 'Freelance gig photo? We need the full-time-unemployed one, chief. LinkedIn profile photo URL'],
    [['xing.com'], 'Xing is LinkedIn for Germans. Close, but no bratwurst, chief'],
    // adult and creator-subscription sites
    [['onlyfans.com', 'manyvids.com', 'fansly.com', 'fanvue.com', 'loyalfans.com', 'justfor.fans', 'fancentro.com', 'clips4sale.com', 'iwantclips.com', 'chaturbate.com', 'stripchat.com', 'pornhub.com', 'phncdn.com', 'xvideos.com', 'xhamster.com', 'redgifs.com'], "I'm honestly shocked. Don't post that photo to LinkedIn, but while you're there, try pasting your LinkedIn profile photo here"],
    // dating
    [['tinder.com', 'gotinder.com', 'bumble.com', 'hinge.co', 'match.com', 'okcupid.com', 'grindr.com'], "That's your dating app pic, chief. We need the one where you look employable. LinkedIn profile photo URL"],
    // entertainment
    [['spotify.com', 'scdn.co'], 'Great playlist, chief. Still not your LinkedIn profile photo'],
    [['twitch.tv', 'jtvnw.net'], "You're live, but you ain't hired. LinkedIn profile photo URL, chief"],
    [['steamcommunity.com', 'steamstatic.com', 'steampowered.com'], 'Steam avatar detected. No achievement unlocked, chief. LinkedIn profile photo URL'],
    [['netflix.com', 'nflximg.net', 'hulu.com', 'disneyplus.com'], "Are you still watching? Because you sure ain't reading. LinkedIn profile photo URL, chief"],
    // search engines
    [['duckduckgo.com', 'yandex.ru', 'yandex.com', 'baidu.com', 'ecosia.org', 'search.brave.com', 'startpage.com', 'perplexity.ai'], 'You pasted the search engine, chief. We need the result, not the search. LinkedIn profile photo URL'],
    // link shorteners
    [['bit.ly', 'tinyurl.com', 'ow.ly', 'buff.ly', 'is.gd', 'rebrand.ly', 'cutt.ly', 'shorturl.at'], 'A short link on a honeypot? Cute trick, chief. Paste the full LinkedIn profile photo URL'],
    [['example.com', 'example.org', 'example.net'], 'example.com? You read the placeholder, chief, just the wrong part. LinkedIn profile photo URL'],
  ];

  const GOV = /(^|\.)(gov|mil|gob|gouv|govt|gv|int)(\.[a-z]{2})?$|(^|\.)go\.[a-z]{2}$|(^|\.)gc\.ca$|(^|\.)canada\.ca$|(^|\.)europa\.eu$|(^|\.)state\.[a-z]{2}\.us$|(^|\.)nhs\.uk$|(^|\.)police\.uk$/;
  const EDU = /(^|\.)(edu|ac\.[a-z]{2}|edu\.[a-z]{2})$/;
  const PRIVATE = /^(localhost|0\.0\.0\.0|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|\[?::1\]?$|.*\.local$|.*\.internal$|.*\.localhost$)/;

  function matches(host, domain) {
    return host === domain || host.endsWith('.' + domain);
  }

  // returns a roast for this URL, or null if we have nothing clever to say
  function forUrl(u) {
    const scheme = u.protocol;
    if (scheme === 'javascript:' || scheme === 'data:' || scheme === 'vbscript:') return "A script in the photo box? On a honeypot? Bold. That ain't it, chief, paste your LinkedIn profile photo URL";
    if (scheme === 'file:') return 'Look, I get that you want to show me a file off your desktop, but put ChatGPT away and show me your LinkedIn profile photo';
    const host = u.hostname.toLowerCase().replace(/\.$/, '');
    if (host === '169.254.169.254' || host === 'metadata.google.internal') return 'Cloud metadata on a honeypot? Look, I get it, you watched one DEF CON talk. Put ChatGPT away and show me your LinkedIn profile photo';
    if (PRIVATE.test(host)) return 'Look, I get that you want to show me your site on localhost, but put ChatGPT away and show me your LinkedIn profile photo';
    if (host === location.hostname) return "That's this site, chief. We ain't doing Inception today. LinkedIn profile photo URL, please";
    if (GOV.test(host)) return pick(STATE);
    if (EDU.test(host)) return "Jeez, still have your school email? That ain't it, chief. Try your LinkedIn profile photo URL";
    if (/(^|\.)google\.[a-z.]{2,6}$/.test(host)) return "You pasted Google? Like, the whole Google? That ain't it, chief. Google your LinkedIn profile photo URL instead";
    if (/mastodon|fediverse/.test(host)) return "Mastodon? Bless your federated heart, but that ain't it, chief. This here is for LinkedIn URLs";
    for (const [domains, msg] of TABLE) {
      if (domains.some((d) => matches(host, d))) return msg;
    }
    return null;
  }

  return { forUrl };
})();
