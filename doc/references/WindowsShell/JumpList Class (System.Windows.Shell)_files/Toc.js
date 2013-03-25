epx=window.epx||{},epx.library=window.epx.library||{},epx.library.toc=function(){function init(){setPadding(),$("#tocnav > div").each(function(){initNode($(this))}),updateIfHighContrastMode(),$("#tocnav a.toc_collapsed").live("click",function(){function addNodesAfter($predecessor,nodes,startIndex,endIndex){for(var nodeHasChildren,childCountId,node,i=startIndex;i>=endIndex;i--)nodeHasChildren=!1,nodes[i].ExtendedAttributes&&nodes[i].ExtendedAttributes[hasSubTreeAttr]&&(nodeHasChildren=nodes[i].ExtendedAttributes[hasSubTreeAttr]==="true"),nodes[i].ExtendedAttributes&&nodes[i].ExtendedAttributes[hasSubTreeAttr]&&(nodeHasChildren=nodes[i].ExtendedAttributes[hasSubTreeAttr]==="true"),childCountId=null,nodes[i].ExtendedAttributes&&nodes[i].ExtendedAttributes["data-childCountId"]&&(childCountId=nodes[i].ExtendedAttributes["data-childCountId"],window.MTPS&&window.MTPS.TopicNodes&&(window.MTPS.TopicNodes[childCountId]=nodes[i].ExtendedAttributes["data-childCount"])),node=buildNode(nodes[i].Href,nodes[i].Title,level+1,!1,nodeHasChildren,childCountId),$predecessor.after(node),window.MTPS&&window.MTPS.Export&&window.MTPS.Export.initViaLink&&window.MTPS.Export.initViaLink($predecessor.next().find("a"));updateIfHighContrastMode()}var href;window.epx.utilities.log("Entering collapsed.click");var $chevron=$(this),$div=$chevron.parent(),level=getLevel($div);return $div.attr(childrenLoadedAttr)==="true"?(window.epx.utilities.log("Child nodes already loaded"),$div.nextUntil("div["+levelAttr+'="'+level+'"]').filter("div["+levelAttr+'="'+(level+1)+'"]').show(),$chevron.attr("class","toc_expanded"),!1):(window.epx.utilities.log("Loading TOC nodes"),href=buildTocHref($chevron.siblings().first().attr("href")),href==undefined||href==null)?!1:($.ajax({type:"GET",async:!0,url:href,dataType:"json",success:function(r){var nodesInserted,$next,$nextLink,nextHref,i,newLevel,$lastSibling;if(!r||r.length<1){window.epx.utilities.log("TOC web service returned 0 nodes.");return}if(window.epx.utilities.log("TOC web service returned "+r.length+" node(s), processing..."),nodesInserted=!1,$next=$div.next(),$next&&($nextLink=$next.children().last(),$nextLink))for(nextHref=$nextLink.attr("href"),i=r.length-1;i>=0;i--)if(window.epx.utilities.endsWith(nextHref,r[i].Href)||window.epx.utilities.endsWith(r[i].Href,nextHref)){for(var paddedAncestors=0,startLevel=parseInt($next.attr(levelAttr)),nextLevel=null;;){if(nextLevel===null){if(nextLevel=startLevel,nextLevel===level+1)break}else if(nextLevel=getLevel($next),nextLevel!==0&&nextLevel<=startLevel)break;if(nextLevel===0&&paddedAncestors++,newLevel=nextLevel+1*paddedAncestors,$next.attr(levelAttr,newLevel),$next.css("padding-"+paddingSide,newLevel*paddingPerLevel+"px"),$next=$next.next(),!$next||!$next.attr(levelAttr))break}addNodesAfter($div,r,i-1,0),$lastSibling=$div.nextUntil("div["+levelAttr+'="'+level+'"]').last(),$lastSibling||($lastSibling=$div.siblings().last()),addNodesAfter($lastSibling,r,r.length-1,i+1),nodesInserted=!0;break}nodesInserted===!1&&addNodesAfter($div,r,r.length-1,0)}}),$div.attr(childrenLoadedAttr,"true"),$chevron.attr("class","toc_expanded"),!1)}),$("#tocnav a.toc_expanded").live("click",function(){return expandClick($(this))})}function initNode($div){var $link=$div.children().last(),level=getLevel($div),current=isCurrent($div),children=hasChildren($div),expanded=children&&current,chevron;expanded===!0&&$div.attr(childrenLoadedAttr,"true"),$div.css("padding-"+paddingSide,level*paddingPerLevel+"px"),chevron=buildChevron(expanded,children),$link.before(chevron),current===!0&&children===!1&&updateParentChevronForLeafNode($div,level)}function updateParentChevronForLeafNode($div,level){var $parent=$div.parent().children("div["+levelAttr+'="'+(level-1)+'"]').last(),parentChevron=buildChevron(!0,!0);$parent.children().length>0&&($parent.children().first().replaceWith(parentChevron),$parent.attr(childrenLoadedAttr,"true"))}function updateIfHighContrastMode(){function updateForHighContrastMode($element,html){$element.html(html).css({width:"auto",height:"auto","margin-top":"0px"})}var $firstChevron=$("a.toc_expanded:first"),$banner;if($firstChevron){switch($firstChevron.css("background-image")){case"":case"none":break;default:return}$("a.toc_expanded").each(function(){updateForHighContrastMode($(this),"-")}),$("a.toc_collapsed").each(function(){updateForHighContrastMode($(this),"+")}),$("span.toc_empty").each(function(){updateForHighContrastMode($(this),"●")}),$banner=$("#tn_header > div.upperBand > a:first"),$banner&&$banner.html($banner.attr("title"))}}function expandClick($chevron){var i,$next;window.epx.utilities.log("Entering expanded.click");var $div=$chevron.parent(),level=getLevel($div),$nextAll=$div.nextAll();if($nextAll&&$nextAll.length>0)for(i=0;i<$nextAll.length;i++)if($next=$($nextAll[i]),getLevel($next)>level)$next.hide(),$next.children("a.toc_expanded").attr("class","toc_collapsed");else break;return $chevron.attr("class","toc_collapsed"),!1}function buildTocHref(baseHref){return baseHref==undefined||baseHref==null?null:baseHref.indexOf("?")===-1?baseHref+"?toc=1":baseHref+"&toc=1"}function buildChevron(expanded,children){var cssClass="toc_empty";return children===!0?(cssClass=expanded===!0?"toc_expanded":"toc_collapsed",chevronFormat.replace("{class}",cssClass)):emptyFormat.replace("{class}",cssClass)}function buildNode(href,title,level,expanded,children,childCountId){var isHrefEmpty=href==null||href==undefined,chevron=buildChevron(expanded,isHrefEmpty?!1:children),nodeTagString;return isHrefEmpty?nodeTagString=nodeSpanTagFormat:(nodeTagString=nodeATagFormat.replace("{href}",href),nodeTagString=nodeTagString.replace("{childCountIdAttribute}",childCountId!=null?'id="'+childCountId+'" ':"")),nodeFormat.replace("{level}",level).replace("{level}",level).replace("{paddingSide}",paddingSide).replace("{padding}",level*paddingPerLevel).replace("{chevron}",chevron).replace("{nodeTag}",nodeTagString.replace(/{text}/gi,window.epx.utilities.htmlEncode(title)))}function getChevron($div){return $div.children().first()}function getLevel($div){return parseInt($div.attr(levelAttr))}function isCurrent($div){var cssClass=$div.attr("class");return cssClass?cssClass.indexOf("current")>=0:!1}function hasChildren($div){return getChevron($div).attr(hasSubTreeAttr)==="true"}function setPadding(){paddingSide=$("html").attr("dir")==="rtl"?"right":"left";var padding=$("#tocPaddingPerLevel").val();padding&&(paddingPerLevel=padding)}var paddingSide="left",paddingPerLevel=13,levelAttr="data-toclevel",childrenLoadedAttr="data-childrenloaded",hasSubTreeAttr="data-tochassubtree",chevronFormat='<a class="{class}" href="#" />',emptyFormat='<span class="{class}" />',nodeFormat='<div class="toclevel{level}" '+levelAttr+'="{level}" style="padding-{paddingSide}: {padding}px;">{chevron}{nodeTag}<\/div>',nodeATagFormat='<a {childCountIdAttribute}href="{href}" title="{text}">{text}<\/a>',nodeSpanTagFormat='<span class="emptyHref">{text}<\/span>';return{init:init,initNode:initNode,expandClick:expandClick,buildTocHref:buildTocHref,buildChevron:buildChevron,buildNode:buildNode,getChevron:getChevron,getLevel:getLevel,isCurrent:isCurrent,hasChildren:hasChildren}}(),$(document).ready(function(){epx.library.toc.init()});