chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "click") {
        const { html, css, js } = message.code;

        // Parse HTML
        const htmlAST = window.htmlParser(html);

        // Parse CSS
        const cssAST = window.postcss.parse(css);

        // Parse JavaScript
        const jsAST = window.acorn.parse(js, { ecmaVersion: 2020 });

        sendResponse({
            htmlAST: JSON.stringify(htmlAST, null, 2),
            cssAST: JSON.stringify(cssAST, null, 2),
            jsAST: JSON.stringify(jsAST, null, 2)
        });
    }
});

chrome.runtime.onInstalled.addListener(() => {
    console.log('Extension installed');
});