import { p as promiseResolve, b as bootstrapLazy } from './index-e2b440e5.js';
export { s as setNonce } from './index-e2b440e5.js';
import { g as globalScripts } from './app-globals-0f993ce5.js';

/*
 Stencil Client Patch Browser v4.22.0 | MIT Licensed | https://stenciljs.com
 */
var patchBrowser = () => {
  const importMeta = import.meta.url;
  const opts = {};
  if (importMeta !== "") {
    opts.resourcesUrl = new URL(".", importMeta).href;
  }
  return promiseResolve(opts);
};

patchBrowser().then(async (options) => {
  await globalScripts();
  return bootstrapLazy([["content-modal_3",[[0,"launchnotes-embed",{"primaryColor":[1,"primary-color"],"heading":[1],"headingColor":[1,"heading-color"],"subheading":[1],"subheadingColor":[1,"subheading-color"],"token":[1],"project":[1],"view":[1],"categories":[1],"widgetPlacement":[1,"widget-placement"],"widgetOffsetSkidding":[2,"widget-offset-skidding"],"widgetOffsetDistance":[2,"widget-offset-distance"],"showUnread":[4,"show-unread"],"unreadPlacement":[1,"unread-placement"],"unreadBackgroundColor":[1,"unread-background-color"],"unreadOffsetSkidding":[2,"unread-offset-skidding"],"unreadOffsetDistance":[2,"unread-offset-distance"],"unreadTextColor":[1,"unread-text-color"],"anonymousUserId":[1,"anonymous-user-id"],"toggleSelector":[1,"toggle-selector"],"hideCategories":[4,"hide-categories"],"hideLNBranding":[4,"hide-l-n-branding"],"backendRootOverride":[1,"backend-root-override"],"useLocalStorage":[4,"use-local-storage"],"widgetFooterHtml":[1,"widget-footer-html"],"setCategories":[32],"announcements":[32],"projectData":[32],"unreadCount":[32],"indicatorElement":[32],"toggleElement":[32],"show":[32],"error":[32],"showContent":[32],"popperInstance":[32],"styleElement":[32],"positionCheckInterval":[32],"unreadPopperInstance":[32],"indicatorScreenPositionX":[32],"indicatorScreenPositionY":[32],"customFooter":[32]},[[8,"click","clickWindow"],[0,"dismissWidget","handleDismissWidget"],[0,"dismissContent","handleDismissContent"]],{"categories":["dataDidChangeHandler"]}],[0,"launchnotes-embed-inline",{"token":[1],"heading":[1],"headingColor":[1,"heading-color"],"subheading":[1],"subheadingColor":[1,"subheading-color"],"project":[1],"view":[1],"categories":[1],"unreadBackgroundColor":[1,"unread-background-color"],"limit":[2],"primaryColor":[1,"primary-color"],"hideCategories":[4,"hide-categories"],"hideLNBranding":[4,"hide-l-n-branding"],"anonymousUserId":[1,"anonymous-user-id"],"backendRootOverride":[1,"backend-root-override"],"useLocalStorage":[4,"use-local-storage"],"setCategories":[32],"error":[32],"showContent":[32],"announcements":[32]},[[0,"dismissContent","handleDismissContent"]],{"categories":["dataDidChangeHandler"]}],[1,"content-modal",{"releaseUrl":[1,"release-url"],"primarycolor":[1],"hideLNBranding":[4,"hide-l-n-branding"],"status":[32]},[[0,"click","handleDismiss"],[8,"message","handleIframeMessage"]]]]]], options);
});

//# sourceMappingURL=launchnotes-embed.js.map