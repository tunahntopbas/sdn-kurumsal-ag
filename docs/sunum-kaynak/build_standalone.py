import json, re, html, sys
root = sys.argv[1]; out = sys.argv[2]
d = json.load(open(f"{root}/deck.json"))
css = open(f"{root}/deck.css").read()
def embed(m):
    attrs, body = m.group(1), m.group(2)
    doc = "<!doctype html><meta charset='utf-8'>" + body
    return f'<iframe{attrs} srcdoc="{html.escape(doc, quote=True)}" frameborder="0" scrolling="no"></iframe>'
slides = []
for sid in d["order"]:
    s = open(f"{root}/slides/{sid}.html").read()
    s = re.sub(r"<x-embed([^>]*)>(.*?)</x-embed>", embed, s, flags=re.S)
    slides.append(s)
fonts = "".join(f'<link rel="stylesheet" href="{f["href"]}">' for f in d["faces"].values())
page = f"""<!doctype html>
<html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(d["title"])}</title>{fonts}
<style>
*{{margin:0}} html,body{{height:100%;background:#0E1013;overflow:hidden}}
body{{font:32px/1.2 sans-serif}}
#stage{{position:absolute;left:50%;top:50%;width:1920px;height:1080px;transform-origin:0 0;counter-reset:page}}
#stage>section{{position:absolute;inset:0;width:1920px;height:1080px;overflow:hidden;box-sizing:border-box;visibility:hidden;isolation:isolate}}
#stage>section.on{{visibility:visible}}
h1{{font-size:96px;font-weight:600}} h2{{font-size:64px;font-weight:600}} h3{{font-size:44px;font-weight:600}}
x-shape,x-icon{{display:block}} x-connector{{display:none}} aside{{display:none}}
iframe{{border:0;background:transparent}}
#notes{{position:fixed;left:0;right:0;bottom:0;max-height:34vh;overflow:auto;background:rgba(14,16,19,.94);color:#E8EAEE;font:16px/1.5 -apple-system,Helvetica,Arial,sans-serif;padding:16px 24px;display:none;z-index:9}}
#notes.show{{display:block}}
#hint{{position:fixed;right:12px;bottom:10px;color:#868D99;font:12px -apple-system,Helvetica,Arial,sans-serif;z-index:8}}
@media print{{html,body{{overflow:visible;background:#fff}} #stage{{position:static;transform:none!important}} #stage>section{{position:relative;visibility:visible;page-break-after:always}} #notes,#hint{{display:none!important}}}}
@page{{size:1920px 1080px;margin:0}}
{css}
</style></head><body>
<div id="stage">
{"".join(slides)}
</div>
<div id="notes"></div>
<div id="hint">← → gezin · F tam ekran · N notlar</div>
<script>
var S=[].slice.call(document.querySelectorAll('#stage>section')),i=0,st=document.getElementById('stage'),nt=document.getElementById('notes');
function fit(){{var k=Math.min(innerWidth/1920,innerHeight/1080);st.style.transform='scale('+k+') translate(-50%,-50%)';st.style.transformOrigin='0 0';st.style.left='50%';st.style.top='50%';st.style.transform='translate(-50%,-50%) scale('+k+')';st.style.transformOrigin='50% 50%';st.style.left='calc(50% - 960px)';st.style.top='calc(50% - 540px)';st.style.transform='scale('+k+')';}}
function go(n){{i=Math.max(0,Math.min(S.length-1,n));S.forEach(function(s,j){{s.classList.toggle('on',j===i)}});var a=S[i].querySelector('aside');nt.textContent=(i+1)+' / '+S.length+'  —  '+(a?a.textContent:'');try{{history.replaceState(null,'','#'+(i+1))}}catch(e){{}}}}
addEventListener('keydown',function(e){{var k=e.key;if(k==='ArrowRight'||k==='PageDown'||k===' ')go(i+1);else if(k==='ArrowLeft'||k==='PageUp')go(i-1);else if(k==='Home')go(0);else if(k==='End')go(S.length-1);else if(k==='f'||k==='F'){{document.fullscreenElement?document.exitFullscreen():document.documentElement.requestFullscreen()}}else if(k==='n'||k==='N')nt.classList.toggle('show');}});
addEventListener('click',function(e){{if(e.target.closest('#notes'))return;go(e.clientX<innerWidth/3?i-1:i+1)}});
addEventListener('resize',fit);fit();go((parseInt(location.hash.slice(1))||1)-1);
</script></body></html>"""
open(out,"w").write(page)
print(len(page))
