"""
Management command: backfill_simhash

Computes and stores SimHash fingerprints for all File records that do not
yet have one (simhash IS NULL).  Safe to run multiple times — already-hashed
files are skipped.

Usage:
    python manage.py backfill_simhash
    python manage.py backfill_simhash --batch-size 50
"""

import os

from django.conf import settings
from django.core.management.base import BaseCommand

from vault.models import File
from vault.workbench.simhash import simhash_file


class Command(BaseCommand):
    help = 'Backfill SimHash fingerprints for all existing samples missing one.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--batch-size',
            type=int,
            default=100,
            help='Number of files to process per DB batch (default: 100).',
        )

    def handle(self, *args, **options):
        batch_size = options['batch_size']
        qs = File.objects.filter(simhash__isnull=True).only('id', 'sha256', 'name')
        total = qs.count()

        if total == 0:
            self.stdout.write(self.style.SUCCESS('All samples already have a SimHash. Nothing to do.'))
            return

        self.stdout.write(f'Found {total} sample(s) without a SimHash. Processing…')

        done = skipped = errors = 0

        for file_obj in qs.iterator(chunk_size=batch_size):
            file_path = os.path.join(settings.SAMPLE_STORAGE_DIR, file_obj.sha256)
            if not os.path.exists(file_path):
                self.stdout.write(
                    self.style.WARNING(f'  [SKIP] {file_obj.sha256[:16]}… — not found on disk')
                )
                skipped += 1
                continue

            try:
                simhash_val, input_size = simhash_file(file_path)
                File.objects.filter(pk=file_obj.pk).update(
                    simhash=simhash_val,
                    simhash_input_size=input_size,
                )
                done += 1
                if done % 10 == 0 or done == total - skipped:
                    self.stdout.write(f'  [{done}/{total - skipped}] hashed')
            except Exception as exc:
                self.stdout.write(
                    self.style.ERROR(f'  [ERROR] {file_obj.sha256[:16]}… — {exc}')
                )
                errors += 1

        self.stdout.write(
            self.style.SUCCESS(
                f'\nDone. hashed={done}  skipped={skipped}  errors={errors}'
            )
        )
