from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('discovery', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='devicediscoveryresult',
            name='extra_outputs',
            field=models.JSONField(blank=True, default=dict),
        ),
    ]
