import inspect

from rest_framework.permissions import BasePermission

from restAPI.api import sequence as sq


######################################################################
# Base permissions definition
######################################################################

class ResourcePermission(BasePermission):
    """
    Base class for define resource permissions.
    """

    enough_perms = None
    global_perms = None
    partial_update_perms = None
    retrieve_perms = None
    create_perms = None
    update_perms = None
    destroy_perms = None
    list_perms = None

    def has_action_permission(self, request, view, action, obj=None):
        permset = getattr(self, "{}_perms".format(action))

        if isinstance(permset, (list, tuple)):
            permset = reduce(lambda acc, v: acc & v, permset)
        elif permset is None:
            # Use empty operator that always return true with
            # empty components.
            permset = And()
        elif isinstance(permset, PermissionComponent):
            # Do nothing
            pass
        elif inspect.isclass(permset) and issubclass(permset, PermissionComponent):
            permset = permset()
        else:
            raise RuntimeError("Invalid permission definition.")

        if self.global_perms:
            permset = (self.global_perms & permset)

        if self.enough_perms:
            permset = (self.enough_perms | permset)

        if obj is None:
            return permset.has_permission(request=request, view=view)
        else:
            return permset.has_object_permission(request=request, view=view, obj=obj)


class PermissionComponent(object):

    def has_permission(self, request, view):
        return True

    def has_object_permission(self, request, view, obj):
        return self.has_permission(request, view)

    def __invert__(self):
        return Not(self)

    def __and__(self, component):
        return And(self, component)

    def __or__(self, component):
        return Or(self, component)


class PermissionOperator(PermissionComponent):
    """
    Base class for all logical operators for compose
    components.
    """

    def __init__(self, *components):
        self.components = tuple(components)


class Not(PermissionOperator):
    """
    Negation operator as permission composable component.
    """

    # Overwrites the default constructor for fix
    # to one parameter instead of variable list of them.
    def __init__(self, component):
        super(Not, self).__init__(component)

    def has_permission(self, *args, **kwargs):
        component = sq.first(self.components)
        return (not component.has_permission(*args, **kwargs))

    def has_object_permission(self, *args, **kwargs):
        component = sq.first(self.components)
        return (not component.has_object_permission(*args, **kwargs))


class Or(PermissionOperator):
    """
    Or logical operator as permission component.
    """

    def has_permission(self, *args, **kwargs):
        valid = False

        for component in self.components:
            if component.has_permission(*args, **kwargs):
                valid = True
                break

        return valid

    def has_object_permission(self, *args, **kwargs):
        valid = False

        for component in self.components:
            if component.has_object_permission(*args, **kwargs):
                valid = True
                break

        return valid


class And(PermissionOperator):
    """
    And logical operator as permission component.
    """

    def has_permission(self, *args, **kwargs):
        valid = True

        for component in self.components:
            if not component.has_permission(*args, **kwargs):
                valid = False
                break

        return valid

    def has_object_permission(self, *args, **kwargs):
        valid = True

        for component in self.components:
            if not component.has_object_permission(*args, **kwargs):
                valid = False
                break

        return valid


######################################################################
# Generic components.
######################################################################


class AllowAny(PermissionComponent):
    def has_permission(self, request, view):
        return True

    def has_object_permission(self, request, view, obj):
        return True


class DenyAll(PermissionComponent):
    def has_permission(self, request, view):
        return False

    def has_object_permission(self, request, view, obj):
        return False


class IsAuthenticated(PermissionComponent):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated()


class IsSuperUser(PermissionComponent):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated() and request.user.is_superuser


class HasMandatoryParam(PermissionComponent):
    def __init__(self, param, *components):
        self.mandatory_param = param
        super(HasMandatoryParam, self).__init__(*components)

    def has_permission(self, request, view):
        param = request.GET.get(self.mandatory_param, None)
        if param:
            return True
        return False


class IsObjectOwner(PermissionComponent):
    def has_object_permission(self, request, view, obj):
        return obj.owner == request.user


######################################################################
# Generic permissions.
######################################################################

class AllowAnyPermission(ResourcePermission):
    enough_perms = AllowAny()


class IsAuthenticatedPermission(ResourcePermission):
    enough_perms = IsAuthenticated()


class DataPermissions(ResourcePermission):
    search_perms = AllowAny()
    upload_sheet_perms = AllowAny()
