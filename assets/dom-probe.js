(() => {
  const marker = 'ferrite_canary';
  const events = [];
  Object.defineProperty(window, '__ferriteDOM', {value: events});
  const record = (sink, value) => {
    if (events.length >= 200) return;
    let text;
    try { text = String(value).slice(0, 4096); } catch { return; }
    if (text.includes(marker)) events.push({kind:'sink', sink, value:text, stack:new Error().stack});
  };
  const wrap = (object, name, arg=0) => {
    const original = object[name];
    if (typeof original !== 'function') return;
    object[name] = function(...args) { record(name,args[arg]); return Reflect.apply(original,this,args); };
  };
  for (const [object,name] of [[Document.prototype,'write'],[Document.prototype,'writeln'],[Element.prototype,'insertAdjacentHTML'],[window,'setTimeout'],[window,'setInterval']]) {
    wrap(object,name,name==='insertAdjacentHTML'?1:0);
  }
  for (const property of ['innerHTML','outerHTML']) {
    const d = Object.getOwnPropertyDescriptor(Element.prototype,property);
    if (d?.set) Object.defineProperty(Element.prototype,property,{...d,set(value){record(property,value);return d.set.call(this,value);}});
  }
  // eval is intentionally left intact: wrapping direct eval changes JavaScript scope.
  addEventListener('message', event => {
    if (events.length < 200) events.push({kind:'message', origin:event.origin, value: typeof event.data==='string'?event.data.slice(0,4096):'[structured message]'});
  });
  addEventListener('DOMContentLoaded', () => {
    if (({}).ferrite_canary !== undefined) events.push({kind:'prototype', value:String(({}).ferrite_canary)});
    const names = new Map();
    for (const el of document.querySelectorAll('[id],[name]')) {
      for (const name of [el.id,el.getAttribute('name')].filter(Boolean)) {
        if (names.has(name) && events.length < 200) events.push({kind:'named-element', name, detail:'Duplicate named element; review for DOM clobbering'});
        names.set(name,el);
      }
    }
  });
})();

// Observational source traces and interaction recording. Values are bounded; no eval wrapping.
(() => {
  const events=window.__ferriteDOM, actions=[];
  Object.defineProperty(window,'__ferriteActions',{value:actions});
  const record=action=>{if(actions.length>=100)return;actions.push(action);try{window.__ferriteRecord?.(JSON.stringify(action));}catch{}};
  const source=(name,value)=>{if(events?.length<200 && typeof value==='string' && value.includes('ferrite_canary'))events.push({kind:'source',source:name,value:value.slice(0,4096),stack:new Error().stack});return value;};
  for(const [proto,name] of [[URLSearchParams.prototype,'get'],[URLSearchParams.prototype,'getAll'],[Storage.prototype,'getItem']]){
    const original=proto[name];
    proto[name]=function(...args){const value=Reflect.apply(original,this,args);source(name,Array.isArray(value)?value.join(','):value);return value;};
  }
  for(const name of ['innerHTML','outerHTML']){
    const d=Object.getOwnPropertyDescriptor(Element.prototype,name);
    if(d?.get)Object.defineProperty(Element.prototype,name,{...d,get(){return source(name,d.get.call(this));}});
  }
  const sink=(name,value)=>{if(events?.length<200&&String(value).includes('ferrite_canary'))events.push({kind:'sink',sink:name,value:String(value).slice(0,4096),stack:new Error().stack});};
  const attribute=Element.prototype.setAttribute;
  Element.prototype.setAttribute=function(name,value){if(/^(src|href|srcdoc|on\w+)$/i.test(name))sink('setAttribute:'+name,value);return Reflect.apply(attribute,this,[name,value]);};
  const fragment=Range.prototype.createContextualFragment;
  Range.prototype.createContextualFragment=function(value){sink('createContextualFragment',value);return Reflect.apply(fragment,this,[value]);};
  const srcdoc=Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype,'srcdoc');
  if(srcdoc?.set)Object.defineProperty(HTMLIFrameElement.prototype,'srcdoc',{...srcdoc,set(value){sink('srcdoc',value);return srcdoc.set.call(this,value);}});
  source('location.href',location.href);
  const selector=e=>{if(e.id)return '#'+CSS.escape(e.id);const path=[];while(e?.nodeType===1){const tag=e.localName;const siblings=e.parentElement?[...e.parentElement.children].filter(x=>x.localName===tag):[];path.unshift(tag+(siblings.length>1?`:nth-of-type(${siblings.indexOf(e)+1})`:''));e=e.parentElement;}return path.join(' > ');};
  addEventListener('change',e=>{if(actions.length<100&&e.target.matches?.('input:not([type=checkbox]):not([type=radio]):not([type=file]),textarea'))record({action:'fill',selector:selector(e.target),value:e.target.value.slice(0,4096)});},true);
  addEventListener('click',e=>{const el=e.target.closest?.('button,a,input[type=submit]');if(el&&actions.length<100)record({action:'click',selector:selector(el)});},true);
})();
