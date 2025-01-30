window.htmlParser = function (html) {
  const parser = new DOMParser();
  return parser.parseFromString(html, 'text/html');
};