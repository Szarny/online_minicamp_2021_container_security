package example

violation[{"msg": msg}] {
    c := input.review.object.spec.containers[_]
    not re_match(".+@sha256:[a-f0-9]{64}", c.image)
    msg := "ダメです"
}

test_allowed_1 {
    input := { 
        "review": {
            "object": {
                "spec": {
                    "containers": [{
                        "name": "allowed_1",
                        "image": "ubuntu@sha256:45b23dee08af5e43a7fea6c4cf9c25ccf269ee113168c19722f87876677c5cb2"
                    }]
                }
            }
        }
    }

    violations := violation with input as input
    count(violations) == 0
}

test_allowed_2 {
    input := { 
        "review": {
            "object": {
                "spec": {
                    "containers": [{
                        "name": "allowed_2",
                        "image": "alpine@sha256:40868330fd6034ce9c0ae903ac4e8161ac47cf6c58e4c440f22323ebab51dcba"
                    }]
                }
            }
        }
    }

    violations := violation with input as input
    count(violations) == 0
}

test_allowed_3 {
    input := { 
        "review": {
            "object": {
                "spec": {
                    "containers": [{
                        "name": "allowed_3_1",
                        "image": "foo/bar@sha256:40868330fd6034ce9c0ae903ac4e8161ac47cf6c58e4c440f22323ebab5133ba"
                    }, {
                        "name": "allowed_3_2",
                        "image": "foo/bar@sha256:40868330fd6034ce9c0ae903ac4e8161ac47cf6c58e4c440f22323ebab5133b1"
                    }]
                }
            }
        }
    }

    violations := violation with input as input
    count(violations) == 0
}

test_allowed_4 {
    input := { 
        "review": {
            "object": {
                "spec": {
                    "containers": [{
                        "name": "allowed_4_1",
                        "image": "foo/bar@sha256:40868330fd6034ce9c0ae903ac4e8161ac47cf6c58e4c440f22323ebab5133ba"
                    }, {
                        "name": "allowed_4_2",
                        "image": "foo/bar@sha256:40868330fd6034ce9c0ae903ac4e8161ac47cf6c58e4c440f22323ebab5133b1"
                    }, {
                        "name": "allowed_4_2",
                        "image": "bar/baz@sha256:40868334343434ce9c0ae903ac4e8161ac47cf6c58e4c440f22323ebab5133b1"
                    }]
                }
            }
        }
    }

    violations := violation with input as input
    count(violations) == 0
}


test_failed_1 {
    input := { 
        "review": {
            "object": {
                "spec": {
                    "containers": [{
                        "name": "failed_1",
                        "image": "ubuntu"
                    }]
                }
            }
        }
    }

    violations := violation with input as input
    
    count(violations) != 0
}

test_failed_2 {
    input := { 
        "review": {
            "object": {
                "spec": {
                    "containers": [{
                        "name": "failed_2",
                        "image": "alpine"
                    }]
                }
            }
        }
    }

    violations := violation with input as input
    count(violations) != 0
}

test_failed_3 {
    input := { 
        "review": {
            "object": {
                "spec": {
                    "containers": [{
                        "name": "failed_3",
                        "image": "ubuntu:focal"
                    }]
                }
            }
        }
    }

    violations := violation with input as input
    count(violations) != 0
}

test_failed_4 {
    input := { 
        "review": {
            "object": {
                "spec": {
                    "containers": [{
                        "name": "failed_4",
                        "image": "nginx:1.21"
                    }]
                }
            }
        }
    }

    violations := violation with input as input
    count(violations) != 0
}

test_failed_5 {
    input := { 
        "review": {
            "object": {
                "spec": {
                    "containers": [{
                        "name": "failed_5",
                        "image": "nginx@sha256:123"
                    }]
                }
            }
        }
    }

    violations := violation with input as input
    count(violations) != 0
}

test_failed_6 {
    input := { 
        "review": {
            "object": {
                "spec": {
                    "containers": [{
                        "name": "failed_6",
                        "image": "nginx@md5:47bce5c74f589f4867dbd57e9ca9f808"
                    }]
                }
            }
        }
    }

    violations := violation with input as input
    count(violations) != 0
}

test_failed_7 {
    input := { 
        "review": {
            "object": {
                "spec": {
                    "containers": [{
                        "name": "failed_7",
                        "image": "@sha256:45b23dee08af5e43a7fea6c4cf9c25ccf269ee113168c19722f87876677c5cb2"
                    }]
                }
            }
        }
    }

    violations := violation with input as input
    count(violations) != 0
}


test_failed_8 {
    input := { 
        "review": {
            "object": {
                "spec": {
                    "containers": [{
                        "name": "failed_8_1",
                        "image": "foo/bar@sha256:40868330fd6034ce9c0ae903ac4e8161ac47cf6c58e4c440f22323ebab5133ba"
                    }, {
                        "name": "failed_8_2",
                        "image": "nginx:1.21"
                    }]
                }
            }
        }
    }

    violations := violation with input as input
    count(violations) != 0
}


test_failed_9 {
    input := { 
        "review": {
            "object": {
                "spec": {
                    "containers": [{
                        "name": "failed_9_1",
                        "image": "foo/bar@sha256:40868330fd6034ce9c0ae903ac4e8161ac47cf6c58e4c440f22323ebab5133ba"
                    }, {
                        "name": "failed_9_2",
                        "image": "nginx@sha256:40868330fd6034ce9c0ae903ac4e8161ac47cf6c58e4c440f22323ebab513xyz"
                    }, {
                        "name": "failed_9_3",
                        "image": "foo/bar@sha256:40868330fd6034ce9c0ae903ac4e8161ac47cf6c58e4c440f22323ebab5133b1"
                    }]
                }
            }
        }
    }

    violations := violation with input as input
    count(violations) != 0
}
