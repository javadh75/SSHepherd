# Pin file only: CI reads this FROM line (Dependabot's docker ecosystem bumps
# tag + digest together). Never built.
FROM aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c
