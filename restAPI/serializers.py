from rest_framework import serializers

from restAPI.models import Content


class ContentSerializer(serializers.Serializer):
    class Meta:
        model = Content
        fields = '__all__'
