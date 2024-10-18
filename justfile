default:
  @just --list

# Add a release tag and publish to the upstream remote. Need write privileges on the repository.
tag crate version remote="upstream":
  # A release tag is specific to a crate so following the convention crate-version.
  echo "Adding release tag {{crate}}-{{version}} and pushing to {{remote}}..."
  # Annotated tag.
  git tag -a {{crate}}-{{version}} -m "Release {{version}} for {{crate}}"
  git push {{remote}} {{crate}}-{{version}}
