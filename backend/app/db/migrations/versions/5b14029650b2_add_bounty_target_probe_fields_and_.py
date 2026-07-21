"""add bounty target probe fields and asset metadata

Revision ID: 5b14029650b2
Revises: b8f8af802a62
Create Date: 2026-07-15 11:16:36.337594

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '5b14029650b2'
down_revision: Union[str, None] = 'b8f8af802a62'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('bounty_assets', sa.Column('metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column('bounty_targets', sa.Column('last_probed_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('bounty_targets', sa.Column('is_alive', sa.Boolean(), nullable=True))
    op.add_column('bounty_targets', sa.Column('probe_metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=True))


def downgrade() -> None:
    op.drop_column('bounty_targets', 'probe_metadata')
    op.drop_column('bounty_targets', 'is_alive')
    op.drop_column('bounty_targets', 'last_probed_at')
    op.drop_column('bounty_assets', 'metadata')
