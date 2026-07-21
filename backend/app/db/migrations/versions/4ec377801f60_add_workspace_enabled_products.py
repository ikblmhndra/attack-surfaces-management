"""add workspace enabled_products for asm/bounty product split

Revision ID: 4ec377801f60
Revises: c7cb7f72c29e
Create Date: 2026-07-20 10:50:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '4ec377801f60'
down_revision: Union[str, None] = 'c7cb7f72c29e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # server_default backfills every pre-existing workspace to ["asm"] --
    # they all predate Bug Bounty entirely, so this preserves their current
    # access exactly. New rows go through the ORM default instead (register()
    # always sets it explicitly from the user's registration choice).
    op.add_column(
        'workspaces',
        sa.Column(
            'enabled_products',
            postgresql.ARRAY(sa.String()),
            nullable=False,
            server_default=sa.text("ARRAY['asm']::varchar[]"),
        ),
    )
    op.alter_column('workspaces', 'enabled_products', server_default=None)


def downgrade() -> None:
    op.drop_column('workspaces', 'enabled_products')
