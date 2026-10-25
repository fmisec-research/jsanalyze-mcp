(function() {
    // panel content is assembled in another chunk; the tracer sees the hop (h = props.body)
    // but not where `props` originates -> a genuine single-file untraced audit sink.
    var h = props.body;
    document.querySelector("#panel").innerHTML = h;
})();