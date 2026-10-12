# Declarations and public installation share the classified tracked inventory.
docs_prose = []
foreach path : source_paths
  if path.startswith('docs/') and path.endswith('.md')
    docs_prose += files(path.substring(5))
  endif
endforeach
