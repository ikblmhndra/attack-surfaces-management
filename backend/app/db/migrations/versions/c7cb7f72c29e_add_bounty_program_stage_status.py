"""add bounty program stage_status

Revision ID: c7cb7f72c29e
Revises: 5b14029650b2
Create Date: 2026-07-16 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'c7cb7f72c29e'
down_revision: Union[str, None] = '5b14029650b2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('bounty_programs', sa.Column('stage_status', postgresql.JSONB(astext_type=sa.Text()), nullable=True))


def downgrade() -> None:
    op.drop_column('bounty_programs', 'stage_status')
