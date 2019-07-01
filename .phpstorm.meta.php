<?php
// This file is not a CODE, it makes no sense and won't run or validate
// Its AST serves IDE as DATA source to make advanced type inference decisions.

namespace PHPSTORM_META {

    use Psr\Container\ContainerInterface;

    override(
        ContainerInterface::get(0),
        map([
            '' => '@',
        ])
    );

    override(\array_add(0), type(0));
    override(\array_except(0), type(0));
    override(\array_first(0), elementType(0));
    override(\array_last(0), elementType(0));
    override(\array_get(0), elementType(0));
    override(\array_only(0), type(0));
    override(\array_prepend(0), type(0));
    override(\array_pull(0), elementType(0));
    override(\array_set(0), type(0));
    override(\array_sort(0), type(0));
    override(\array_sort_recursive(0), type(0));
    override(\array_where(0), type(0));
    override(\head(0), elementType(0));
    override(\last(0), elementType(0));
    override(\with(0), type(0));
}