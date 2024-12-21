from rest_framework.serializers import ModelSerializer

from .models import GmailToken


class GmailTokenSerializer(ModelSerializer):
    class Meta:
        model = GmailToken
        fields = ["token", "refresh_token", "created_at", "updated_at"]
